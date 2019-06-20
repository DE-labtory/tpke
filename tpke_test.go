package tpke

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"github.com/bls"
	"github.com/leesper/go_rng"
	"math/big"
	"testing"
)

type playGround struct {
	actors []*actor
	pkSet *PublicKeySet
}

func (pg *playGround) publishPubKey() *PublicKey {
	return pg.pkSet.PublicKey()
}

func (pg *playGround) startDecMeeting() *decryptionMeeting {
	return &decryptionMeeting {
		pkSet: *pg.pkSet.Clone(),
		cipherText: nil,

		decShares: make(map[int]*DecryptionShare),
	}
}

type actor struct {
	id int
	skShare *SecretKeyShare
	pkShare *PublicKeyShare
	receivedMsg *CipherText
}

type decryptionMeeting struct {
	pkSet PublicKeySet
	cipherText *CipherText
	decShares map[int]*DecryptionShare
}

func (dm *decryptionMeeting) acceptDecShare(a *actor) {
	cipherText := a.receivedMsg
	decShare := a.skShare.DecryptShare(cipherText.Clone())
	dm.decShares[a.id] = decShare
}

func (dm *decryptionMeeting) decrypt() ([]byte, error) {
	cipherText := dm.cipherText.Clone()
	return dm.pkSet.Decrypt(dm.decShares, cipherText)
}

func sendMessage(a *actor, ct *CipherText) {
	a.receivedMsg = ct
}

func setUp(t *testing.T) *playGround {
	th := 2
	people := 5
	secretKeySet := randomSecretKeySet(th)
	publicKeySet := secretKeySet.publicKeySet()

	actors := make([]*actor, 0)
	i := 0
	for i < people {
		actors = append(actors, &actor{
			id: i,
			skShare: secretKeySet.keyShare(i),
			pkShare: publicKeySet.KeyShare(i),
		})
		i++
	}
	return &playGround {
		actors: actors,
		pkSet: publicKeySet,
	}
}

func TestTPKE(t *testing.T) {
	playGround := setUp(t)
	pk := playGround.publishPubKey()

	alice := playGround.actors[0].id
	bob := playGround.actors[1].id
	clara := playGround.actors[2].id
	david := playGround.actors[3].id
	eric := playGround.actors[4].id

	msg := []byte("pizza pizza")
	t.Logf("msg : %v", msg)
	cipherText, err := pk.Encrypt(msg)

	sendMessage(playGround.actors[alice], cipherText.Clone())
	sendMessage(playGround.actors[bob], cipherText.Clone())
	sendMessage(playGround.actors[clara], cipherText.Clone())
	sendMessage(playGround.actors[david], cipherText.Clone())
	sendMessage(playGround.actors[eric], cipherText.Clone())

	if err != nil {
		t.Logf("error : %v", err)
	}

	t.Logf("cipher text : %v", cipherText)

	meeting := playGround.startDecMeeting()
	meeting.cipherText = cipherText.Clone()

	meeting.acceptDecShare(playGround.actors[alice])
	meeting.acceptDecShare(playGround.actors[bob])
	_, err1 := meeting.decrypt()

	if err1 != nil {
		t.Logf("%v", err1)
	}

	meeting.acceptDecShare(playGround.actors[clara])
	res2, _ := meeting.decrypt()
	t.Logf("res2: %v", res2)
	t.Logf("res2(string): %v", string(res2))

	meeting.acceptDecShare(playGround.actors[david])
	res3, err3 := meeting.decrypt()

	if err3 != nil {
		t.Logf("%v", err)
	}

	t.Logf("res3: %v", res3)
	t.Logf("res3(string): %v", string(res3))

	meeting.acceptDecShare(playGround.actors[eric])
	res4, err4 := meeting.decrypt()

	if err4 != nil {
		t.Logf("%v", err)
	}

	t.Logf("res4: %v", res4)
	t.Logf("res4(string): %v", string(res4))
}

func TestInterpolate(t *testing.T) {
	deg := []int{0, 1, 2, 3, 4, 5}
	rng := rng.NewUniformGenerator(1231245)
	for i := range deg {
		t.Logf("deg : %v", deg[i])
		items := make([]*Sample, 0)
		comm := randomPoly(deg[i]).commitment()
		x := 1
		for j := 0; j <= deg[i]; j++ {
			x += int(rng.Int32()) % 5 + 1
			xFR := bls.FRReprToFR(bls.NewFRRepr(uint64(x)))
			sample := &Sample {
				fr: bls.FRReprToFR(bls.NewFRRepr(uint64(x))),
				g1: comm.evaluate(*xFR),
			}
			items = append(items, sample)
		}
		FRZero := bls.FRReprToFR(bls.NewFRRepr(0))
		actual, _ := Interpolate(deg[i], items)
		expected := comm.evaluate(*FRZero)
		t.Logf("eval 0 : %v", expected)
		t.Logf("actual : %v", actual)
		t.Logf("equals : %v", expected.Equal(actual))
	}
}

func TestEncrypt(t *testing.T) {
	sk_bob := randomSecretKey(2000)
	//sk_eve := randomSecretKey()
	pk_bob := sk_bob.PublicKey()
	msg := []byte("Hello world!")

	cipherText, _ := pk_bob.Encrypt(msg)
	t.Logf("verify: %v", cipherText.Verify())
}

func randomSecretKey(n int) *SecretKey {

	fr := bls.FRReprToFR(bls.NewFRRepr(uint64(n)))

	//frRepr := &bls.FRRepr{3140105163220197741, 15199066853698796999, 617359497624618578, 6843342860022209944}

	return &SecretKey {
		FR: fr,
	}

}

func TestSimpleEnc(t *testing.T) {
	skBob := randomSecretKey(121321123)
	pkBob := skBob.PublicKey()
	msg := []byte("hello world!")
	cipher, _ := pkBob.Encrypt(msg)
	decrypted := skBob.Decrypt(cipher)
	t.Logf("%v", string(decrypted))
}

func TestHashG2(t *testing.T) {
	msg := []byte("hello world")
	a := HashG2(msg)
	b := HashG2(msg)
	t.Logf("%v", a)
	t.Logf("%v", b)
}

func TestSimpleSig(t *testing.T) {
	//sk0 := randomSecretKey(1000)
	k, _ := bls.RandFR(rand.Reader)
	sk0 := &SecretKey{
		FR: k,
	}

	pk0 := &PublicKey {
		G1: bls.G1AffineOne.MulFR(sk0.FR.ToRepr()),
	}
	msg0 := []byte("hello world")
	var b [32]byte
	hash := hashFunc(msg0)
	for i := range hash {
		b[i] = hash[i]
	}
	t.Logf("b : %v", b)
	//hashG2 := HashG2WithDomain(b, 1)
	hashG2 := bls.HashG2(msg0)
	//hashG2 := bls.HashG2WithDomain(b, 1)
	t.Logf("hashG2 : %v", hashG2)
	sig := hashG2.MulFR(sk0.FR.ToRepr())
	p1 := bls.Pairing(pk0.G1, hashG2.ToProjective())
	p2 := bls.Pairing(bls.G1ProjectiveOne, sig)
	t.Logf("%v", p1)
	t.Logf("%v", p2)
	t.Logf("%v", p1.Equals(p2))
}

func TestLibrary(t *testing.T) {
	denom, _ := bls.RandFR(rand.Reader)
	inv := denom.Inverse()
	t.Logf("%v", inv)
	denom.MulAssign(inv)
	t.Logf("%v", denom)
}

// hashFunc returns the SHA-256 hash of the input
func hashFunc(in []byte) []byte {
	h := sha256.New()
	h.Write(in)
	return h.Sum(nil)
}
func HashG2WithDomain(messageHash [32]byte, domain uint64) *bls.G2Projective {
	var domainBytes [8]byte
	binary.BigEndian.PutUint64(domainBytes[:], domain)

	xReBytes := append(messageHash[:], domainBytes[:]...)
	xReBytes = append(xReBytes, '\x01')

	xImBytes := append(messageHash[:], domainBytes[:]...)
	xImBytes = append(xImBytes, '\x02')

	xRe := new(big.Int)
	xRe.SetBytes(hashFunc(xReBytes))

	xIm := new(big.Int)
	xIm.SetBytes(hashFunc(xImBytes))

	// hash function is only 256 bits so this will never overflow
	xReFQ, _ := bls.FQReprFromBigInt(xRe)
	xImFQ, _ := bls.FQReprFromBigInt(xIm)

	x0 := bls.NewFQ2(bls.FQReprToFQ(xReFQ), bls.FQReprToFQ(xImFQ))

	for {
		gx0 := x0.Copy()
		gx0.SquareAssign()
		gx0.MulAssign(x0)

		gx0.AddAssign(bls.BCoeffFQ2)

		y0, found := gx0.Sqrt()

		if found {
			// favor the lower y value
			if !y0.Parity() {
				y0.NegAssign()
			}

			return bls.NewG2Affine(x0, y0).ScaleByCofactor()
		}

		x0.AddAssign(bls.FQ2One)
	}
}

func TestInterpolate2(t *testing.T) {

	fqRepr1x := bls.FQRepr{9938611223284109106, 10215607719061052334, 15821107287498947032, 88067207736890365, 11465573793138902341, 1547831325428317150}
	fqRepr1y := bls.FQRepr{1942079225551245600, 7610096908681529964, 16322158364699821629, 398674700505965757, 1023125790101921123, 1687861123878944856}
	fqRepr1z := bls.FQRepr{2530751463620143334, 5080238956006029316, 10695410662960626370, 4627209263171646528, 17627945417427180901, 917527079834353344}

	fqRepr2x := bls.FQRepr{14383587668233311728, 596027317513951601, 17680637274814213476, 16900835674168689792, 845822411821194099, 236830744168181381}
	fqRepr2y := bls.FQRepr{10187416114789797956, 17782487468500979965, 12768190218146435726, 17340088784365197038, 11477473610976829901, 1070246271458655653}
	fqRepr2z := bls.FQRepr{16324176591712470762, 12225032344133016748, 1334391821236429583, 6553964585048012521, 5029621685222656816, 1284074802879163406}

	samples := []*Sample{
		{
			fr: bls.FRReprToFR(bls.NewFRRepr(1)),
			g1: bls.NewG1Projective(bls.FQReprToFQRaw(fqRepr1x), bls.FQReprToFQRaw(fqRepr1y), bls.FQReprToFQRaw(fqRepr1z)),
		},
		{
			fr: bls.FRReprToFR(bls.NewFRRepr(2)),
			g1: bls.NewG1Projective(bls.FQReprToFQRaw(fqRepr2x), bls.FQReprToFQRaw(fqRepr2y), bls.FQReprToFQRaw(fqRepr2z)),
		},
	}

	g, _ := Interpolate(1, samples)
	t.Logf("%v", g)
	// PASS
}