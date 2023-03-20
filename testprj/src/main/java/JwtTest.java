import java.text.ParseException;
import java.util.Date;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObject;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
  * @파일명 : JwtTest.java
  * @작성일 : 2023. 3. 19.
  * @작성자 : 김영철
  */

/**
 * @프로젝트명 : testprj
 * @패키지명 :
 * @파일명 : JwtTest.java
 * @작성일 : 2023. 3. 19.
 * @작성자 : 김영철
 */
public class JwtTest {

    /**
     * @메소드타입 : JwtTest
     * @메소드명 : main
     * @return : void
     * @param args
     * @throws JOSEException
     * @throws ParseException
     */
    @SuppressWarnings("unused")
    public static void main(String[] args) throws JOSEException, ParseException {

        // 현재 시간
        long longIat = new Date().getTime();
        String strIat = Long.toString(longIat);

        // 만료 시간
        long longExp = new Date().getTime() + 1000 * 60L * 60L * 2L; // 2시간
        String strExp = Long.toString(longExp);

        // 정보 (payload)
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                // registered claims
                .issuer("aihub.com").subject("user_authentification").audience("ironman")
                .expirationTime(new Date(longExp)).notBeforeTime(new Date(longIat)).issueTime(new Date(longIat))
                .jwtID("avengers")
                // public claims
                .claim("https://aihub.com/jwt_claims/is_amdin", true)
                // private claims
                .claim("userid", "ironman").claim("username", "tony_stark").build();

        System.out.println(claimsSet.toString());

        // 헤더 (header) HMAC SHA256
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

        System.out.println(JWSAlgorithm.HS256);
        System.out.println(new JWSHeader(JWSAlgorithm.HS256));

        // 서명 (signature) key is 256bit(32bytes) over ...
        String key = "fTjWnZq4t7w!z%C*F-JaNdRgUkXp2s5u";
        JWSSigner signer = new MACSigner(key);
        signedJWT.sign(signer);

        String jwtString = signedJWT.serialize();
        System.out.println(jwtString);

        System.out.println("-------------------------------------------------------");
        System.out.println("-------------------------------------------------------");

        JWT signedJWT1 = (SignedJWT) SignedJWT.parse(jwtString);

        // check payload and applied algorithm in header
        Map<String, Object> map = ((JOSEObject) signedJWT1).getPayload().toJSONObject();
        System.out.println(map.get("userid"));
        System.out.println(((JOSEObject) signedJWT1).getPayload().toJSONObject());
        System.out.println(signedJWT1.getHeader().getAlgorithm());

        // verification with signature
        JWSVerifier verifier = new MACVerifier(key);
        boolean isValid = SignedJWT.parse(jwtString).verify(verifier);
        System.out.println(isValid);
    }
}
