/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package msp

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	x509GM "github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/hyperledger/fabric/bccsp/gm"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/common/tools/cryptogen/ca"
	"github.com/hyperledger/fabric/common/tools/cryptogen/csp"
	fabricmsp "github.com/hyperledger/fabric/msp"
	"gopkg.in/yaml.v2"
)

const (
	CLIENT = iota
	ORDERER
	PEER
	ADMIN
)

const (
	CLIENTOU  = "client"
	PEEROU    = "peer"
	ADMINOU   = "admin"
	ORDEREROU = "orderer"
)

var nodeOUMap = map[int]string{
	CLIENT:  CLIENTOU,
	PEER:    PEEROU,
	ADMIN:   ADMINOU,
	ORDERER: ORDEREROU,
}

func GenerateLocalMSP(baseDir, name string, sans []string, signCA *ca.CA,
	tlsCA *ca.CA, nodeType int, nodeOUs bool) error {

	// create folder structure
	mspDir := filepath.Join(baseDir, "msp")
	tlsDir := filepath.Join(baseDir, "tls")

	err := createFolderStructure(mspDir, true)
	if err != nil {
		return err
	}

	err = os.MkdirAll(tlsDir, 0755)
	if err != nil {
		return err
	}

	/*
		Create the MSP identity artifacts
	*/
	// get keystore path
	keystore := filepath.Join(mspDir, "keystore")

	var cert *x509.Certificate

	if gm.IsX509SM2Certificate(signCA.SignCert) {
		priv, _, err := csp.GenerateSM2PrivateKey(keystore)
		if err != nil {
			return err
		}

		// get public key
		ecPubKey, err := csp.GetSM2PublicKey(priv)
		if err != nil {
			return err
		}

		// generate private key
		// generate X509 certificate using signing CA
		var ous []string
		if nodeOUs {
			ous = []string{nodeOUMap[nodeType]}
		}
		cert, err = signCA.SignGMCertificate(filepath.Join(mspDir, "signcerts"),
			name, ous, nil, ecPubKey, x509GM.KeyUsageDigitalSignature, []x509GM.ExtKeyUsage{})
		if err != nil {
			return err
		}
	} else {
		priv, _, err := csp.GeneratePrivateKey(keystore)
		if err != nil {
			return err
		}

		// get public key
		ecPubKey, err := csp.GetECPublicKey(priv)
		if err != nil {
			return err
		}

		// generate private key
		// generate X509 certificate using signing CA
		var ous []string
		if nodeOUs {
			ous = []string{nodeOUMap[nodeType]}
		}
		cert, err = signCA.SignCertificate(filepath.Join(mspDir, "signcerts"),
			name, ous, nil, ecPubKey, x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{})
		if err != nil {
			return err
		}
	}

	// write artifacts to MSP folders

	// the signing CA certificate goes into cacerts
	err = x509Export(filepath.Join(mspDir, "cacerts", x509Filename(signCA.Name)), signCA.SignCert)
	if err != nil {
		return err
	}
	// the TLS CA certificate goes into tlscacerts
	err = x509Export(filepath.Join(mspDir, "tlscacerts", x509Filename(tlsCA.Name)), tlsCA.SignCert)
	if err != nil {
		return err
	}

	// generate config.yaml if required
	if nodeOUs {

		exportConfig(mspDir, filepath.Join("cacerts", x509Filename(signCA.Name)), true)
	}

	// the signing identity goes into admincerts.
	// This means that the signing identity
	// of this MSP is also an admin of this MSP
	// NOTE: the admincerts folder is going to be
	// cleared up anyway by copyAdminCert, but
	// we leave a valid admin for now for the sake
	// of unit tests
	if !nodeOUs {
		err = x509Export(filepath.Join(mspDir, "admincerts", x509Filename(name)), cert)
		if err != nil {
			return err
		}
	}

	/*
		Generate the TLS artifacts in the TLS folder
	*/

	var tlsPrivKey bccsp.Key

	if gm.IsX509SM2Certificate(tlsCA.SignCert) {
		// generate private key
		tlsPrivKey, _, err = csp.GenerateSM2PrivateKey(tlsDir)
		if err != nil {
			return err
		}
		// get public key
		tlsPubKey, err := csp.GetSM2PublicKey(tlsPrivKey)
		if err != nil {
			return err
		}
		// generate X509 certificate using TLS CA
		_, err = tlsCA.SignGMCertificate(filepath.Join(tlsDir),
			name, nil, sans, tlsPubKey, x509GM.KeyUsageDigitalSignature|x509GM.KeyUsageKeyEncipherment,
			[]x509GM.ExtKeyUsage{x509GM.ExtKeyUsageServerAuth, x509GM.ExtKeyUsageClientAuth})
	} else {
		// generate private key
		tlsPrivKey, _, err = csp.GeneratePrivateKey(tlsDir)
		if err != nil {
			return err
		}
		// get public key
		tlsPubKey, err := csp.GetECPublicKey(tlsPrivKey)
		if err != nil {
			return err
		}
		// generate X509 certificate using TLS CA
		_, err = tlsCA.SignCertificate(filepath.Join(tlsDir),
			name, nil, sans, tlsPubKey, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	}

	if err != nil {
		return err
	}
	err = x509Export(filepath.Join(tlsDir, "ca.crt"), tlsCA.SignCert)
	if err != nil {
		return err
	}

	// rename the generated TLS X509 cert
	tlsFilePrefix := "server"
	if nodeType == CLIENT || nodeType == ADMIN {
		tlsFilePrefix = "client"
	}
	err = os.Rename(filepath.Join(tlsDir, x509Filename(name)),
		filepath.Join(tlsDir, tlsFilePrefix+".crt"))
	if err != nil {
		return err
	}

	err = keyExport(tlsDir, filepath.Join(tlsDir, tlsFilePrefix+".key"), tlsPrivKey)
	if err != nil {
		return err
	}

	return nil
}

func GenerateVerifyingMSP(baseDir string, signCA *ca.CA, tlsCA *ca.CA, nodeOUs bool) error {

	// create folder structure and write artifacts to proper locations
	err := createFolderStructure(baseDir, false)
	if err == nil {
		// the signing CA certificate goes into cacerts
		err = x509Export(filepath.Join(baseDir, "cacerts", x509Filename(signCA.Name)), signCA.SignCert)
		if err != nil {
			return err
		}
		// the TLS CA certificate goes into tlscacerts
		err = x509Export(filepath.Join(baseDir, "tlscacerts", x509Filename(tlsCA.Name)), tlsCA.SignCert)
		if err != nil {
			return err
		}
	}

	// generate config.yaml if required
	if nodeOUs {
		exportConfig(baseDir, "cacerts/"+x509Filename(signCA.Name), true)
	}

	// create a throwaway cert to act as an admin cert
	// NOTE: the admincerts folder is going to be
	// cleared up anyway by copyAdminCert, but
	// we leave a valid admin for now for the sake
	// of unit tests
	if nodeOUs {
		return nil
	}


	if gm.IsX509SM2Certificate(signCA.SignCert) {
		f := &factory.GMFactory{}
		bcsp, err := f.Get(factory.GetGMOpts())
		if err != nil {
			return err
		}
		priv, err := bcsp.KeyGen(&bccsp.GMSM2KeyGenOpts{Temporary: true})
		sm2PubKey, err := csp.GetSM2PublicKey(priv)
		if err != nil {
			return err
		}
		_, err = signCA.SignGMCertificate(filepath.Join(baseDir, "admincerts"), signCA.Name,
			nil, nil, sm2PubKey, x509GM.KeyUsageDigitalSignature, []x509GM.ExtKeyUsage{})
		if err != nil {
			return err
		}
	} else {
		f := &factory.SWFactory{}
		bcsp, err := f.Get(factory.GetDefaultOpts())
		if err != nil {
			return err
		}
		priv, err := bcsp.KeyGen(&bccsp.ECDSAP256KeyGenOpts{Temporary: true})
		ecPubKey, err := csp.GetECPublicKey(priv)
		if err != nil {
			return err
		}
		_, err = signCA.SignCertificate(filepath.Join(baseDir, "admincerts"), signCA.Name,
			nil, nil, ecPubKey, x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{})
		if err != nil {
			return err
		}
	}

	return nil
}

func createFolderStructure(rootDir string, local bool) error {

	var folders []string
	// create admincerts, cacerts, keystore and signcerts folders
	folders = []string{
		filepath.Join(rootDir, "admincerts"),
		filepath.Join(rootDir, "cacerts"),
		filepath.Join(rootDir, "tlscacerts"),
	}
	if local {
		folders = append(folders, filepath.Join(rootDir, "keystore"),
			filepath.Join(rootDir, "signcerts"))
	}

	for _, folder := range folders {
		err := os.MkdirAll(folder, 0755)
		if err != nil {
			return err
		}
	}

	return nil
}

func x509Filename(name string) string {
	return name + "-cert.pem"
}

func x509Export(path string, cert *x509.Certificate) error {
	return pemExport(path, "CERTIFICATE", cert.Raw)
}

func keyExport(keystore, output string, key bccsp.Key) error {
	id := hex.EncodeToString(key.SKI())

	return os.Rename(filepath.Join(keystore, id+"_sk"), output)
}

func pemExport(path, pemType string, bytes []byte) error {
	//write pem out to file
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{Type: pemType, Bytes: bytes})
}

func exportConfig(mspDir, caFile string, enable bool) error {
	var config = &fabricmsp.Configuration{
		NodeOUs: &fabricmsp.NodeOUs{
			Enable: enable,
			ClientOUIdentifier: &fabricmsp.OrganizationalUnitIdentifiersConfiguration{
				Certificate:                  caFile,
				OrganizationalUnitIdentifier: CLIENTOU,
			},
			PeerOUIdentifier: &fabricmsp.OrganizationalUnitIdentifiersConfiguration{
				Certificate:                  caFile,
				OrganizationalUnitIdentifier: PEEROU,
			},
			AdminOUIdentifier: &fabricmsp.OrganizationalUnitIdentifiersConfiguration{
				Certificate:                  caFile,
				OrganizationalUnitIdentifier: ADMINOU,
			},
			OrdererOUIdentifier: &fabricmsp.OrganizationalUnitIdentifiersConfiguration{
				Certificate:                  caFile,
				OrganizationalUnitIdentifier: ORDEREROU,
			},
		},
	}

	configBytes, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	file, err := os.Create(filepath.Join(mspDir, "config.yaml"))
	if err != nil {
		return err
	}

	defer file.Close()
	_, err = file.WriteString(string(configBytes))

	return err
}
