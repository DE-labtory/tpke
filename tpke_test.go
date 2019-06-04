package tpke

import (
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
	receivedMsg CipherText
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

func (dm *decryptionMeeting) decrypt() []byte {
	cipherText := dm.cipherText.Clone()
	return dm.pkSet.Decrypt(dm.decShares, &cipherText)
}

func sendMessage(a *actor, ct CipherText) {
	a.receivedMsg = ct
}

func setUp(t *testing.T) *playGround {
	th := 2
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

	msg := []byte("hello world!")
	cipherText, err := pk.Encrypt(msg)

	sendMessage(&playGround.actors[alice], cipherText.Clone())
	sendMessage(&playGround.actors[bob], cipherText.Clone())
	sendMessage(&playGround.actors[clara], cipherText.Clone())

	if err != nil {
		t.Logf("error : %v", err)
	}

	t.Logf("cipher text : %v", cipherText)

	meeting := playGround.startDecMeeting()
	meeting.acceptDecShare(playGround.actors[alice])
}