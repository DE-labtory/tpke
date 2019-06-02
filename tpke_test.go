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

type actor struct {
	id int
	skShare *SecretKeyShare
	pkShare *PublicKeyShare
	receivedMsg CipherText
}

func sendMessage(id int, ct CipherText) {

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

	if err != nil {
		t.Logf("error : %v", err)
	}

	t.Logf("cipher text : %v", cipherText)
}