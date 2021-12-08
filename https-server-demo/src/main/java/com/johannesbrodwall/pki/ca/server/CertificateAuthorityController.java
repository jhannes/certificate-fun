package com.johannesbrodwall.pki.ca.server;

import com.johannesbrodwall.pki.ca.CertificateAuthority;
import com.johannesbrodwall.pki.infrastructure.Multipart;
import com.johannesbrodwall.pki.infrastructure.OpenIdAuthenticationFilter;
import com.johannesbrodwall.pki.util.SslUtil;
import com.johannesbrodwall.pki.util.SunCertificateUtil;
import org.actioncontroller.actions.POST;
import org.actioncontroller.exceptions.HttpRequestException;
import org.actioncontroller.values.ContentBody;
import org.actioncontroller.values.HttpHeader;
import org.actioncontroller.values.RequestParam;
import org.actioncontroller.values.UserPrincipal;
import sun.security.pkcs10.PKCS10;
import sun.security.util.DerValue;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.X500Name;
import sun.security.x509.X509Key;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Optional;
import java.util.function.Consumer;

public class CertificateAuthorityController {

    private CertificateAuthority certificateAuthority;

    @POST("/privateKey")
    @ContentBody(contentType = "application/x-pkcs12")
    public byte[] issuePrivateKey(
            @UserPrincipal Optional<OpenIdAuthenticationFilter.OpenIdPrincipal> userPrincipal,
            @RequestParam("commonName") Optional<String> commonName,
            @HttpHeader("Content-Disposition") Consumer<String> setContentDisposition
    ) throws GeneralSecurityException, IOException {
        String subjectName;
        String name;
        if (userPrincipal.isPresent()) {
            String email = userPrincipal.get().getUserinfo().requiredString("unique_name");
            name = userPrincipal.get().getUserinfo().requiredString("name");
            String domain = email.substring(email.indexOf('@') + 1);
            subjectName = "CN=" + name + ",O=" + domain + ",EMAIL=" + email;
            if (commonName.isPresent()) {
                subjectName += ",CN=" + commonName.get();
            }
        } else if (commonName.isPresent()) {
            name = commonName.get();
            subjectName = "CN=" + name;
        } else {
            throw new HttpRequestException("Missing user");
        }


        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        X509Certificate certificate = certificateAuthority.issueClientCertificate(subjectName, ZonedDateTime.now(), keyPair.getPublic());
        KeyStore keyStore = SslUtil.createKeyStore(keyPair.getPrivate(), null, certificate);
        setContentDisposition.accept("attachment; filename=\"" + name + ".p12\"");
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        keyStore.store(buffer, "".toCharArray());
        return buffer.toByteArray();
    }


    @POST("/certificateRequest")
    @ContentBody(contentType = "text/html")
    public String requestCertificate(
            @Multipart("certificateRequestFile") String data
    ) throws IOException, SignatureException, NoSuchAlgorithmException {
        PKCS10 pkcs10 = new PKCS10(SslUtil.parsePemString(data));
        CertificateExtensions certificateExtensions = SunCertificateUtil.getCertificateExtensions(pkcs10);
        String extensions = "";
        if (certificateExtensions != null) {
            extensions = "<div><label>Extensions: <br /><input name=extensions type=checkbox checked value='" + data + "' />" + certificateExtensions + "</label></div>";
        }
        return "<form method=post action='issueCertificate'>" +
               "<div><label>Subject name: <br /><input name=subjectName type=text size=150 value='" + pkcs10.getSubjectName() + "' /></label></div>" +
               extensions +
               "<input name=publicKey type=hidden value='" + Base64.getEncoder().encodeToString(pkcs10.getSubjectPublicKeyInfo().getEncoded()) + "' />" +
               "<div><button>Confirm</button></div>" +
               "</form>";
    }

    @POST("/issueCertificate")
    @ContentBody(contentType = "application/pkix-cert")
    public String issueCertificate(
            @RequestParam("subjectName") String subjectName,
            @RequestParam("publicKey") String base64PublicKey,
            @RequestParam("extensions") Optional<String> extensionsInPemCsr,
            @HttpHeader("Content-Disposition") Consumer<String> setContentDisposition
    ) throws IOException, GeneralSecurityException {
        X509Certificate certificate = certificateAuthority.issueCertificate(
                subjectName,
                ZonedDateTime.now(),
                X509Key.parse(new DerValue(Base64.getDecoder().decode(base64PublicKey.getBytes()))),
                extensionsInPemCsr.map(SslUtil::parsePemString)
        );

        String filename = ((X500Name) certificate.getSubjectDN()).getCommonName() + ".crt";
        setContentDisposition.accept("attachment; filename=\"" + filename + "\"");
        return SslUtil.writePemString(certificate.getEncoded(), "CERTIFICATE");
    }

    public void setCertificateAuthority(CertificateAuthority certificateAuthority) {
        this.certificateAuthority = certificateAuthority;
    }
}
