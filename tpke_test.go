package tpke

import (
	"crypto/rand"
	"github.com/phoreproject/bls"
	"testing"
)

type playGround struct {
	actors []actor
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

func (dm *decryptionMeeting) acceptDecShare(a actor) {
	cipherText := a.receivedMsg
	decShare := a.skShare.DecryptShare(cipherText)
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
	th := 1
	people := 3
	secretKeySet := randomSecretKeySet(th)
	publicKeySet := secretKeySet.publicKeySet()

	actors := make([]actor, people)
	for i := range actors {
		actors[i] = actor{
			id: i,
			skShare: secretKeySet.keyShare(i),
			pkShare: publicKeySet.KeyShare(i),
		}
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

	msg := []byte("let's get pizza")
	t.Logf("msg : %v", msg)
	cipherText, err := pk.Encrypt(msg)

	sendMessage(&playGround.actors[alice], cipherText.Clone())
	sendMessage(&playGround.actors[bob], cipherText.Clone())
	sendMessage(&playGround.actors[clara], cipherText.Clone())

	if err != nil {
		t.Logf("error : %v", err)
	}

	t.Logf("cipher text : %v", cipherText)

	meeting := playGround.startDecMeeting()
	meeting.cipherText = cipherText.Clone()
	meeting.acceptDecShare(playGround.actors[alice])
	meeting.acceptDecShare(playGround.actors[bob])
	meeting.acceptDecShare(playGround.actors[clara])
	res, err := meeting.decrypt()

	if err != nil {
		t.Logf("error : %v", err)
	}
	t.Logf("res: %v", res)
	t.Logf("res(string): %v", string(res))
}

func TestXorHash(t *testing.T) {
	g0, _ := bls.RandG1(rand.Reader)
	g1, _ := bls.RandG1(rand.Reader)
	arr := []byte{0, 1, 2, 3, 4, 5}
	r1, _ := xorHash(*g0, arr)
	r2, _ := xorHash(*g0, arr)

	r3, _ := xorHash(*g1, arr)
	r4, _ := xorHash(*g1, arr)

	t.Logf("r1 : %v", r1)
	t.Logf("r2 : %v", r2)
	t.Logf("r3 : %v", r3)
	t.Logf("r4 : %v", r4)
}

func TestInterpolate(t *testing.T) {
	deg := []int{0, 1, 2, 3, 4, 5}
	// rng := rng2.NewUniformGenerator(12345)
	for i := range deg {
		t.Logf("deg : %v", deg[i])
		//items := make([]*bls.G1Projective, 0)
		items := make([]*Sample, 0)
		comm := randomPoly(deg[i]).commitment()
		x := 1
		for j := 0; j <= deg[i]; j++ {
			//x += int(rng.Int32()) % 5 + 1
			x += 1
			xFR := bls.FRReprToFR(bls.NewFRRepr(uint64(x)))
			// eval := comm.evaluate(*xFR)
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