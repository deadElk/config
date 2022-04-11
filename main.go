package main

import (
	"time"

	log "github.com/sirupsen/logrus"
	// "golang.org/x/crypto/ssh"
)

func init() {
	log.SetLevel(_S_Verbosity)
	log.SetFormatter(&log.TextFormatter{
		ForceColors:               false,
		DisableColors:             false,
		ForceQuote:                true,
		DisableQuote:              false,
		EnvironmentOverrideColors: false,
		DisableTimestamp:          false,
		FullTimestamp:             true,
		TimestampFormat:           time.RFC3339Nano,
		DisableSorting:            true,
		SortingFunc:               nil,
		DisableLevelTruncation:    false,
		PadLevelText:              true,
		QuoteEmptyFields:          true,
		FieldMap:                  nil,
		CallerPrettyfier:          nil,
	})
	log.SetReportCaller(false)
}

func main() {
	defer log.Infof("done")
	log.Infof("start")

	// var (
	// 	idata = "-----BEGIN CERTIFICATE-----\nMIICWjCCAbygAwIBAgIHBdvBJy1ZxzAKBggqhkjOPQQDBDAqMRMwEQYDVQQKEwpk\nb21haW4udGxkMRMwEQYDVQQDEwpkb21haW4udGxkMB4XDTIyMDQwMzE0NTE1NloX\nDTMwMDEwMTAwMDAwMFowLDETMBEGA1UEChMKZG9tYWluLnRsZDEVMBMGA1UEAwwM\nKi5kb21haW4udGxkMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBb1J4p1AtghYi\n1qyTAR0fVmwxq1He8tJgCWoGYy4RFeh7La5AzK0jRzkIjb8uSYF40a4OA/N8DaN1\nsB3kfw46uZ4AUJXpd/NNR7q69U6bJ2z4T+IZ/klYsGhZ90yUeqaxYueiXdq23nZJ\ntACDXhY76i8GptJ1f9bYoJs9FF4rGK4Kx7qjgYcwgYQwDgYDVR0PAQH/BAQDAgeA\nMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAfBgNVHSMEGDAWgBTUe2Uw\nTO8OsPpSQW+RH2mcmRdJ3DAyBgNVHREEKzApggpkb21haW4udGxkggwqLmRvbWFp\nbi50bGSBDW5zQGRvbWFpbi50bGQwCgYIKoZIzj0EAwQDgYsAMIGHAkIAucQJ4ja8\nQ96yt5b9jYZ+asPvm+KIxbhs+6tOxCPa0Vx+EWcY/7ZFQsGhBTtpJFx2qs8Kbbwu\noVQp0U1zfn0X7A4CQReH3NqNdJKEyQBWvX5zYcyOFdfttfV/RP8nID3PX+qQqKs7\nY4o6Gl0ewslJ1CvnYbZWayBwOchPUUTtat7a1xWK\n-----END CERTIFICATE-----\n-----BEGIN EC PRIVATE KEY-----\nMIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAbPKvmvD+v9hne4i2\nlVUyWfVyqyOItpzJBYN6r1pIHoRgN7b7StANGmaHJ5ek7nq6Jx6Vnd5qND3Cvj9o\nVtF12aehgYkDgYYABAFvUninUC2CFiLWrJMBHR9WbDGrUd7y0mAJagZjLhEV6Hst\nrkDMrSNHOQiNvy5JgXjRrg4D83wNo3WwHeR/Djq5ngBQlel3801Hurr1TpsnbPhP\n4hn+SViwaFn3TJR6prFi56Jd2rbedkm0AINeFjvqLwam0nV/1tigmz0UXisYrgrH\nug==\n-----END EC PRIVATE KEY-----\n"
	// 	odata = [][]byte{}
	// )
	//
	// for {
	// 	var (
	// 		t = pem.Decode([]byte(idata))
	// 	)
	//
	// }

	i_file.read()

	define_iDB_Vocabulary()
	i_vi_ip.generate(_S_VI_IPPrefix, _VIx_IF_bits)
	i_ui_ip.generate(_S_UI_IPPrefix, _UIx_IP_bits)

	read_cDB()

	parse_iDB_Vocabulary()
	generate_iDB_host_list()

	read_ldap()
	parse_LDAP()

	i_peer.parse_GT()

	i_file.write()
	i_file_link.write()
	write_ldap()
}

// func genCA() {
// 	// get our ca and server certificate
// 	serverTLSConf, clientTLSConf, err := certsetup()
// 	if err != nil {
// 		panic(err)
// 	}
//
// 	// set up the httptest.Server using our certificate signed by our CA
// 	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		fmt.Fprintln(w, "success!")
// 	}))
// 	server.TLS = serverTLSConf
// 	server.StartTLS()
// 	defer server.Close()
//
// 	// communicate with the server using an http_client.Client configured to trust our CA
// 	transport := &http.Transport{
// 		TLSClientConfig: clientTLSConf,
// 	}
// 	http_client := http.Client{
// 		Transport: transport,
// 	}
// 	resp, err := http_client.Get(server.URL)
// 	if err != nil {
// 		panic(err)
// 	}
//
// 	// verify the response
// 	respBodyBytes, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		panic(err)
// 	}
// 	body := _strings.TrimSpace(string(respBodyBytes[:]))
// 	if body == "success!" {
// 		fmt.Println(body)
// 	} else {
// 		panic("not successful!")
// 	}
// }
// func certsetup() (serverTLSConf *tls.Config, clientTLSConf *tls.Config, err error) {
// 	// set up our CA certificate
// 	ca := &x509.Certificate{
// 		SerialNumber: big.NewInt(2019),
// 		Subject: pkix.Name{
// 			Organization:  []string{"Company, INC."},
// 			Country:       []string{"US"},
// 			Province:      []string{""},
// 			Locality:      []string{"San Francisco"},
// 			StreetAddress: []string{"Golden Gate Bridge"},
// 			PostalCode:    []string{"94016"},
// 		},
// 		NotBefore:             time.Now(),
// 		NotAfter:              time.Now().AddDate(10, 0, 0),
// 		IsCA:                  true,
// 		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
// 		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
// 		BasicConstraintsValid: true,
// 		CRLDistributionPoints: []string{},
// 	}
//
// 	// create our private and public key
// 	caPrivKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
// 	if err != nil {
// 		return nil, nil, err
// 	}
//
// 	// create the CA
// 	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
// 	if err != nil {
// 		return nil, nil, err
// 	}
//
// 	// pem encode
// 	caPEM := new(bytes.Buffer)
// 	pem.Encode(caPEM, &pem.Block{
// 		Type:  "CERTIFICATE",
// 		Bytes: caBytes,
// 	})
//
// 	caPrivKeyPEM := new(bytes.Buffer)
// 	pem.Encode(caPrivKeyPEM, &pem.Block{
// 		Type:  "EC PRIVATE KEY",
// 		Bytes: parse_interface(x509.MarshalECPrivateKey(caPrivKey)).([]byte),
// 	})
// 	log.Infof("%v", caPrivKeyPEM)
// 	// set up our server certificate
// 	cert := &x509.Certificate{
// 		SerialNumber: big.NewInt(2019),
// 		Subject: pkix.Name{
// 			Organization:  []string{"Company, INC."},
// 			Country:       []string{"US"},
// 			Province:      []string{""},
// 			Locality:      []string{"San Francisco"},
// 			StreetAddress: []string{"Golden Gate Bridge"},
// 			PostalCode:    []string{"94016"},
// 		},
// 		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
// 		NotBefore:    time.Now(),
// 		NotAfter:     time.Now().AddDate(10, 0, 0),
// 		SubjectKeyId: []byte{1, 2, 3, 4, 6},
// 		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
// 		KeyUsage:     x509.KeyUsageDigitalSignature,
// 	}
//
// 	certPrivKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
// 	if err != nil {
// 		return nil, nil, err
// 	}
//
// 	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
// 	if err != nil {
// 		return nil, nil, err
// 	}
//
// 	certPEM := new(bytes.Buffer)
// 	pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
// 	log.Infof("%v", certPEM)
//
// 	certPrivKeyPEM := new(bytes.Buffer)
// 	pem.Encode(certPrivKeyPEM, &pem.Block{
// 		Type:  "EC PRIVATE KEY",
// 		Bytes: parse_interface(x509.MarshalECPrivateKey(certPrivKey)).([]byte),
// 	})
//
// 	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
// 	if err != nil {
// 		return nil, nil, err
// 	}
//
// 	serverTLSConf = &tls.Config{
// 		Certificates: []tls.Certificate{serverCert},
// 	}
//
// 	certpool := x509.NewCertPool()
// 	certpool.AppendCertsFromPEM(caPEM.Bytes())
// 	clientTLSConf = &tls.Config{
// 		RootCAs: certpool,
// 	}
//
// 	return
// }
