import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import java.util.regex.Pattern;

/**
 * Tool to generate a pair of codeVerifier + challenge from codeVerifier
 * by applying S256 method to codeVerifier. This is compliant with
 * PKCE RFC 7636 and enforced both the minimum and maximum entropy values,
 * and length. A regexp pattern is also used to check the codeVerifier
 * is compliant with section 2.3 RFC 3986. You can also enter a custom
 * codeVerifier and get the S256(codeVerifier) expected for OpenID/OAuth2
 * clients. This is a basic Eclipse projet + Java API only1
 * 
 * https://tools.ietf.org/html/rfc7636
 * https://tools.ietf.org/html/rfc3986
 * 
 * This code is in the public domain. Do whatever you want with it.
 * If you really want a license let's say it's BSD without attribution.
 * 
 * @author Gilbert Fernandes <gilbert.fernandes@orange.fr>
 *
 */
public class S256Code {
	
	static final int MINIMUM_ENTROPY = 32;
	static final int MAXIMUM_ENTROPY = 96;
	static final int DEFAULT_ENTROPY = 64;
	
	static final int MINIMUM_LENGTH =  43;
	static final int MAXIMUM_LENGTH = 128;
	
	final static String REGEX_PATTERN = "^[0-9a-zA-Z\\-\\.\\_\\~]{43,128}$";
	final static Pattern REGEX_VERIFIER = Pattern.compile(REGEX_PATTERN);

	public static void main(String[] args) throws NoSuchAlgorithmException,
	                                              IOException {
		
		int input = getTask();
		
		switch(input) {
		
		case 0 :
			// exit program
			return;
		case 1 :
			// generate code and S256 hash
			final String codeVerifier = generateCodeVerifier();
			assert(codeVerifier.length() >= MINIMUM_LENGTH && codeVerifier.length() <= MAXIMUM_LENGTH);
			assert(REGEX_VERIFIER.matcher(codeVerifier).matches());
			System.out.println("codeVerifier = " + codeVerifier);
			System.out.println("challenge    = " + generateChallenge(codeVerifier));
			return;
			
		case 2 :
			// generate S256 from custom codeVerifier
			final String manualCodeVerifier = getCodeVerifier();
			assert(manualCodeVerifier.length() >= MINIMUM_LENGTH && manualCodeVerifier.length() <= MAXIMUM_LENGTH);
			assert(REGEX_VERIFIER.matcher(manualCodeVerifier).matches());
			System.out.println("codeVerifier = " + manualCodeVerifier);
			System.out.println("challenge    = " + generateChallenge(manualCodeVerifier));
			return;
			
		default :
			System.out.println("bug in code : value not in [0,1,2]");
			return;
			
		}
	}

	private static String getCodeVerifier() throws IOException {
		@SuppressWarnings("resource")
		Scanner sc = new Scanner(System.in);
        sc.useDelimiter("\\n");
        System.out.print("\ncodeVerifier ? ");
        String input = null;
        
        do {
        	input = sc.nextLine();
        	if(sc != null) {
        		if(input.length() < MINIMUM_LENGTH || input.length() > MAXIMUM_LENGTH) {
        			input = "";
        			System.out.println("codeVerifier must be >= " + MINIMUM_LENGTH +
        					                           " and <= " + MAXIMUM_LENGTH + "\n");
        			continue;
        		}
        		if(!REGEX_VERIFIER.matcher(input).matches()) {
        			System.out.println("codeVerifier MUST match regexp pattern " + REGEX_PATTERN + "\n");
        			input = "";
        			continue;
        		}
        	}
        } while(input.isEmpty());
        
        return input;
	}

	/**
	 * Produces a challenge from a code verifier, using SHA-256 as the challenge method
	 * + ISO-8859-1 encoding + Base64 encoding
	 * @param codeVerifier
	 * @return string
	 * @throws NoSuchAlgorithmException if SHA-256 is unavailable
	 * @throws UnsupportedEncodingException if encoding is not ISO-8859-1 
	 */
	private static String generateChallenge(String codeVerifier)
			throws NoSuchAlgorithmException,
	               UnsupportedEncodingException {
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		sha256.update(codeVerifier.getBytes("ISO_8859_1"));
		byte[] bytes = sha256.digest();
		// code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
		// with codeVerifier as ISO8859-1 ASCII
		// RFC 7636 section 4.2
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);		
	}

	/**
	 * code_verifier = high-entropy cryptographic random STRING using the
	 * unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
	 * from Section 2.3 of [RFC3986], with a minimum length of 43 characters
	 * and a maximum length of 128 characters.
	 * @return string
	 */
	private static String generateCodeVerifier() {
		SecureRandom entropy = new SecureRandom();
		int entropyLength = DEFAULT_ENTROPY;
		
		assert(entropy != null);
		assert(entropyLength >= MINIMUM_ENTROPY);
		assert(entropyLength <= MAXIMUM_ENTROPY);
		
		byte[] bytes = new byte[entropyLength];
		entropy.nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	private static int getTask() {
		
		System.out.println("S256Code - v.1.0 - Gilbert Fernandes\n");
		System.out.println("0. Exit");
		System.out.println("1. Generate a codeVerifier and S256 hash");
		System.out.println("2. Calculate hash from codeVerifier");
		
		int input = -1;
		@SuppressWarnings("resource")
		Scanner in = new Scanner(System.in);
		
		do {
			System.out.print("\nChoice ? ");
			try {
				if(in.hasNext()) {
					input = in.nextInt();
				}
				if(input != 0 && input != 1 && input != 2) {
					System.out.println("Unknown choice");
				}
			} catch (Exception e) {
				System.out.println("Number expected");
				in.nextLine(); // remove invalid entry
			}
		}
		while(input != 0 && input != 1 && input != 2);
		return input;
	}

}
