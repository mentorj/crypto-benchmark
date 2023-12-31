package com.decathlon.cg.benchmarks;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.vavr.control.Try;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.Date;
import java.util.concurrent.TimeUnit;



@BenchmarkMode(Mode.Throughput)
@Warmup(timeUnit = TimeUnit.SECONDS,time = 5)
@Fork(value=4)
/**
 * benchmark for a couple of crypto algorithms, providers with different strength
 * Aimed to drive choice regarding algorithm adoption in Login product
 * @author J.MOLIERE
 */
public class CryptoBenchmark {


    @State(Scope.Group)
    public static class BenchmarkState {

        private final static byte[] mod = {
                (byte)177, (byte)119, (byte) 33, (byte) 13, (byte)164, (byte) 30, (byte)108, (byte)121,
                (byte)207, (byte)136, (byte)107, (byte)242, (byte) 12, (byte)224, (byte) 19, (byte)226,
                (byte)198, (byte)134, (byte) 17, (byte) 71, (byte)173, (byte) 75, (byte) 42, (byte) 61,
                (byte) 48, (byte)162, (byte)206, (byte)161, (byte) 97, (byte)108, (byte)185, (byte)234,
                (byte)226, (byte)219, (byte)118, (byte)206, (byte)118, (byte)  5, (byte)169, (byte)224,

                (byte) 60, (byte)181, (byte) 90, (byte) 85, (byte) 51, (byte)123, (byte)  6, (byte)224,
                (byte)  4, (byte)122, (byte) 29, (byte)230, (byte)151, (byte) 12, (byte)244, (byte)127,
                (byte)121, (byte) 25, (byte)  4, (byte) 85, (byte)220, (byte)144, (byte)215, (byte)110,
                (byte)130, (byte) 17, (byte) 68, (byte)228, (byte)129, (byte)138, (byte)  7, (byte)130,
                (byte)231, (byte) 40, (byte)212, (byte)214, (byte) 17, (byte)179, (byte) 28, (byte)124,

                (byte)151, (byte)178, (byte)207, (byte) 20, (byte) 14, (byte)154, (byte)222, (byte)113,
                (byte)176, (byte) 24, (byte)198, (byte) 73, (byte)211, (byte)113, (byte)  9, (byte) 33,
                (byte)178, (byte) 80, (byte) 13, (byte) 25, (byte) 21, (byte) 25, (byte)153, (byte)212,
                (byte)206, (byte) 67, (byte)154, (byte)147, (byte) 70, (byte)194, (byte)192, (byte)183,
                (byte)160, (byte) 83, (byte) 98, (byte)236, (byte)175, (byte) 85, (byte) 23, (byte) 97,

                (byte) 75, (byte)199, (byte)177, (byte) 73, (byte)145, (byte) 50, (byte)253, (byte)206,
                (byte) 32, (byte)179, (byte)254, (byte)236, (byte)190, (byte) 82, (byte) 73, (byte) 67,
                (byte)129, (byte)253, (byte)252, (byte)220, (byte)108, (byte)136, (byte)138, (byte) 11,
                (byte)192, (byte)  1, (byte) 36, (byte)239, (byte)228, (byte) 55, (byte) 81, (byte)113,
                (byte) 17, (byte) 25, (byte)140, (byte) 63, (byte)239, (byte)146, (byte)  3, (byte)172,

                (byte) 96, (byte) 60, (byte)227, (byte)233, (byte) 64, (byte)255, (byte)224, (byte)173,
                (byte)225, (byte)228, (byte)229, (byte) 92, (byte)112, (byte) 72, (byte) 99, (byte) 97,
                (byte) 26, (byte) 87, (byte)187, (byte)123, (byte) 46, (byte) 50, (byte) 90, (byte)202,
                (byte)117, (byte) 73, (byte) 10, (byte)153, (byte) 47, (byte)224, (byte)178, (byte)163,
                (byte) 77, (byte) 48, (byte) 46, (byte)154, (byte) 33, (byte)148, (byte) 34, (byte)228,

                (byte) 33, (byte)172, (byte)216, (byte) 89, (byte) 46, (byte)225, (byte)127, (byte) 68,
                (byte)146, (byte)234, (byte) 30, (byte)147, (byte) 54, (byte)146, (byte)  5, (byte)133,
                (byte) 45, (byte) 78, (byte)254, (byte) 85, (byte) 55, (byte) 75, (byte)213, (byte) 86,
                (byte)194, (byte)218, (byte)215, (byte)163, (byte)189, (byte)194, (byte) 54, (byte)  6,
                (byte) 83, (byte) 36, (byte) 18, (byte)153, (byte) 53, (byte)  7, (byte) 48, (byte) 89,

                (byte) 35, (byte) 66, (byte)144, (byte)  7, (byte) 65, (byte)154, (byte) 13, (byte) 97,
                (byte) 75, (byte) 55, (byte)230, (byte)132, (byte)  3, (byte) 13, (byte)239, (byte) 71  };

        private static final byte[] exp= { 1, 0, 1 };


        private static final byte[] modPriv = {
                (byte) 84, (byte) 80, (byte)150, (byte) 58, (byte)165, (byte)235, (byte)242, (byte)123,
                (byte)217, (byte) 55, (byte) 38, (byte)154, (byte) 36, (byte)181, (byte)221, (byte)156,
                (byte)211, (byte)215, (byte)100, (byte)164, (byte) 90, (byte) 88, (byte) 40, (byte)228,
                (byte) 83, (byte)148, (byte) 54, (byte)122, (byte)  4, (byte) 16, (byte)165, (byte) 48,
                (byte) 76, (byte)194, (byte) 26, (byte)107, (byte) 51, (byte) 53, (byte)179, (byte)165,

                (byte) 31, (byte) 18, (byte)198, (byte)173, (byte) 78, (byte) 61, (byte) 56, (byte) 97,
                (byte)252, (byte)158, (byte)140, (byte) 80, (byte) 63, (byte) 25, (byte)223, (byte)156,
                (byte) 36, (byte)203, (byte)214, (byte)252, (byte)120, (byte) 67, (byte)180, (byte)167,
                (byte)  3, (byte) 82, (byte)243, (byte) 25, (byte) 97, (byte)214, (byte) 83, (byte)133,
                (byte) 69, (byte) 16, (byte)104, (byte) 54, (byte)160, (byte)200, (byte) 41, (byte) 83,

                (byte)164, (byte)187, (byte) 70, (byte)153, (byte)111, (byte)234, (byte)242, (byte)158,
                (byte)175, (byte) 28, (byte)198, (byte) 48, (byte)211, (byte) 45, (byte)148, (byte) 58,
                (byte) 23, (byte) 62, (byte)227, (byte) 74, (byte) 52, (byte)117, (byte) 42, (byte) 90,
                (byte) 41, (byte)249, (byte)130, (byte)154, (byte) 80, (byte)119, (byte) 61, (byte) 26,
                (byte)193, (byte) 40, (byte)125, (byte) 10, (byte)152, (byte)174, (byte)227, (byte)225,

                (byte)205, (byte) 32, (byte) 62, (byte) 66, (byte)  6, (byte)163, (byte)100, (byte) 99,
                (byte)219, (byte) 19, (byte)253, (byte) 25, (byte)105, (byte) 80, (byte)201, (byte) 29,
                (byte)252, (byte)157, (byte)237, (byte) 69, (byte)  1, (byte) 80, (byte)171, (byte)167,
                (byte) 20, (byte)196, (byte)156, (byte)109, (byte)249, (byte) 88, (byte)  0, (byte)  3,
                (byte)152, (byte) 38, (byte)165, (byte) 72, (byte) 87, (byte)  6, (byte)152, (byte) 71,

                (byte)156, (byte)214, (byte) 16, (byte) 71, (byte) 30, (byte) 82, (byte) 51, (byte)103,
                (byte) 76, (byte)218, (byte) 63, (byte)  9, (byte) 84, (byte)163, (byte)249, (byte) 91,
                (byte)215, (byte) 44, (byte)238, (byte) 85, (byte)101, (byte)240, (byte)148, (byte)  1,
                (byte) 82, (byte)224, (byte) 91, (byte)135, (byte)105, (byte)127, (byte) 84, (byte)171,
                (byte)181, (byte)152, (byte)210, (byte)183, (byte)126, (byte) 24, (byte) 46, (byte)196,

                (byte) 90, (byte)173, (byte) 38, (byte)245, (byte)219, (byte)186, (byte)222, (byte) 27,
                (byte)240, (byte)212, (byte)194, (byte) 15, (byte) 66, (byte)135, (byte)226, (byte)178,
                (byte)190, (byte) 52, (byte)245, (byte) 74, (byte) 65, (byte)224, (byte) 81, (byte)100,
                (byte) 85, (byte) 25, (byte)204, (byte)165, (byte)203, (byte)187, (byte)175, (byte) 84,
                (byte)100, (byte) 82, (byte) 15, (byte) 11, (byte) 23, (byte)202, (byte)151, (byte)107,

                (byte) 54, (byte) 41, (byte)207, (byte)  3, (byte)136, (byte)229, (byte)134, (byte)131,
                (byte) 93, (byte)139, (byte) 50, (byte)182, (byte)204, (byte) 93, (byte)130, (byte)89   };

        @Param({"ES256"})
        public String algoStrenth;


        private JWTClaimsSet claimsSet;
        private OctetKeyPair jwk;

        private JWSSigner signer;

        private OctetKeyPair publicJWK;
        @Setup(Level.Invocation)
        public void setUpBenchmark(){
            //algoName = JWSAlgorithm.parse(algoStrenth);
            // Generate a key pair with Ed25519 curve
            Try<OctetKeyPair> jwkTry = Try.of(() ->new OctetKeyPairGenerator(Curve.Ed25519)
                    .keyID("123")
                    .generate());
            jwk = jwkTry.get();
            publicJWK = jwk.toPublicJWK();

// Create the EdDSA signer
            signer = Try.of(() -> new Ed25519Signer(jwk)).get();

// Prepare JWT with claims set
             claimsSet= new JWTClaimsSet.Builder()
                    .subject("test")
                    .issuer("https://decathlon.com")
                    .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                    .build();


        }

        @Benchmark
        @Group(value = "ED25519")
        @Timeout(time = 1,timeUnit = TimeUnit.MINUTES)
        public String signWithED25519(){
            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(jwk.getKeyID()).build(),
                    claimsSet);
            try{
                signedJWT.sign(signer);
            }catch(Exception e){
                e.printStackTrace();
            }
            return signedJWT.serialize();

        }

        @Benchmark
        @Group(value = "ED25519")
        @Timeout(time = 1,timeUnit = TimeUnit.MINUTES)
        public void signAndVerifyWithED25519(Blackhole bh){
            String outcome = signWithED25519();
            try {
                SignedJWT signedJWT = SignedJWT.parse(outcome);
                JWSVerifier verifier = new Ed25519Verifier(publicJWK);
                bh.consume(signedJWT.verify(verifier));
            } catch (ParseException e) {
                throw new RuntimeException(e);
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }

        }

        @Benchmark
        @Group(value = "RSA")
        @Timeout(time = 1,timeUnit = TimeUnit.MINUTES)
        public void signAndVerifyWithRSA(Blackhole bh){
            String outcome = signWithRSA();

            KeyFactory keyFactory = null;
            try {
                keyFactory = KeyFactory.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(new BigInteger(1, mod), new BigInteger(1, modPriv));
            RSAPrivateKey privateKey = null;
            try {
                privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
            EncryptedJWT jwt = null;
            try {
                jwt = EncryptedJWT.parse(outcome);
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
            RSADecrypter decrypter = new RSADecrypter(privateKey);
            try {
                jwt.decrypt(decrypter);
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }
        }

        @Benchmark
        @Group(value = "RSA")
        @Timeout(time = 1,timeUnit = TimeUnit.MINUTES)
        public String signWithRSA(){


            KeyFactory keyFactory = null;
            try {
                keyFactory = KeyFactory.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }

            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(1, mod), new BigInteger(1, exp));


            RSAPublicKey publicKey = null;
            try {
                publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
            JWEHeader header = new JWEHeader(
                    JWEAlgorithm.RSA_OAEP_256,
                    EncryptionMethod.A128GCM
            );

            EncryptedJWT jwt = new EncryptedJWT(header, claimsSet);
            RSAEncrypter encrypter = new RSAEncrypter(publicKey);
            try {
                jwt.encrypt(encrypter);
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }

            return jwt.serialize();

        }
    }
}
