import java.io.IOException;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.parameters.RSAPkcsOaepParameters;
import iaik.pkcs.pkcs11.parameters.RsaAesKeyWrapParameters;
import iaik.pkcs.pkcs11.parameters.RSAPkcsOaepParameters.SourceType;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

public class RSA_AES_KEY_WRAP_mech {
    static char[] pin_ocs = "comsys2019".toCharArray();
    static String p11_lib_path = "/opt/nfast/toolkits/pkcs11/libcknfast.so";
    static int login_slot = 1;

    public static void main(String[] args) throws TokenException {
        try {
            Module p11 = Module.getInstance(p11_lib_path);
            p11.initialize(null);

            Slot[] slots = p11.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);

            if (slots.length == 0) {
                System.out.println("No slot with present token found!");
                throw new TokenException("No token found!");
            }

            for (int i = 0; i < slots.length; i++) {
                System.out.println("slot name " + i + " :" + slots[i].getSlotInfo().getSlotDescription());
            }

            Token token = slots[login_slot].getToken(); /* Get slot ID */
            Session hSession = token.openSession(Token.SessionType.SERIAL_SESSION,
                    Token.SessionReadWriteBehavior.RW_SESSION, null, null);
            hSession.login(Session.UserType.USER, pin_ocs);

            // generation RSA KEY
            /* Setup the template for the wrapping key. */
            byte[] publicExponentBytes = { 0x01, 0x00, 0x01 }; // 2^16 + 1

            RSAPublicKey wrapping_pub_key_attributeTemplateList = new RSAPublicKey();
            wrapping_pub_key_attributeTemplateList.getLabel().setCharArrayValue("TEST_IAIK_RSA_KEY".toCharArray());
            wrapping_pub_key_attributeTemplateList.getKeyType().setLongValue(PKCS11Constants.CKK_RSA);
            wrapping_pub_key_attributeTemplateList.getEncrypt().setBooleanValue(PKCS11Constants.TRUE);
            wrapping_pub_key_attributeTemplateList.getWrap().setBooleanValue(PKCS11Constants.TRUE);
            wrapping_pub_key_attributeTemplateList.getToken().setBooleanValue(PKCS11Constants.FALSE);
            wrapping_pub_key_attributeTemplateList.getPrivate().setBooleanValue(PKCS11Constants.TRUE);
            wrapping_pub_key_attributeTemplateList.getModulusBits().setLongValue((long)2048);
            wrapping_pub_key_attributeTemplateList.getPublicExponent().setByteArrayValue(publicExponentBytes);

            RSAPrivateKey wrapping_priv_key_attributeTemplateList = new RSAPrivateKey();
            wrapping_priv_key_attributeTemplateList.getLabel().setCharArrayValue("TEST_IAIK_RSA_KEY".toCharArray());
            wrapping_priv_key_attributeTemplateList.getKeyType().setLongValue(PKCS11Constants.CKK_RSA);
            wrapping_priv_key_attributeTemplateList.getDecrypt().setBooleanValue(PKCS11Constants.TRUE);
            wrapping_priv_key_attributeTemplateList.getUnwrap().setBooleanValue(PKCS11Constants.TRUE);
            wrapping_priv_key_attributeTemplateList.getToken().setBooleanValue(PKCS11Constants.FALSE);
            wrapping_priv_key_attributeTemplateList.getPrivate().setBooleanValue(PKCS11Constants.TRUE);
            wrapping_priv_key_attributeTemplateList.getSensitive().setBooleanValue(Boolean.TRUE);

            /* Setup the template for the key. */

            RSAPublicKey pub_key_attributeTemplateList = new RSAPublicKey();
            pub_key_attributeTemplateList.getLabel().setCharArrayValue("TEST_IAIK_RSA_KEY".toCharArray());
            pub_key_attributeTemplateList.getKeyType().setLongValue(PKCS11Constants.CKK_RSA);
            pub_key_attributeTemplateList.getEncrypt().setBooleanValue(PKCS11Constants.TRUE);
            pub_key_attributeTemplateList.getWrap().setBooleanValue(PKCS11Constants.TRUE);
            pub_key_attributeTemplateList.getToken().setBooleanValue(PKCS11Constants.FALSE);
            pub_key_attributeTemplateList.getPrivate().setBooleanValue(PKCS11Constants.TRUE);
            pub_key_attributeTemplateList.getModulusBits().setLongValue((long)2048);
            pub_key_attributeTemplateList.getPublicExponent().setByteArrayValue(publicExponentBytes);

            RSAPrivateKey priv_key_attributeTemplateList = new RSAPrivateKey();
            priv_key_attributeTemplateList.getLabel().setCharArrayValue("TEST_IAIK_RSA_KEY".toCharArray());
            priv_key_attributeTemplateList.getKeyType().setLongValue(PKCS11Constants.CKK_RSA);
            priv_key_attributeTemplateList.getDecrypt().setBooleanValue(PKCS11Constants.TRUE);
            priv_key_attributeTemplateList.getUnwrap().setBooleanValue(PKCS11Constants.TRUE);
            priv_key_attributeTemplateList.getToken().setBooleanValue(PKCS11Constants.FALSE);
            priv_key_attributeTemplateList.getPrivate().setBooleanValue(PKCS11Constants.TRUE);
            priv_key_attributeTemplateList.getSensitive().setBooleanValue(Boolean.TRUE);
            priv_key_attributeTemplateList.getExtractable().setBooleanValue(Boolean.TRUE);

            try {
                
                Mechanism rsagen_mcha = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
                KeyPair wrapping_key = hSession.generateKeyPair(rsagen_mcha, wrapping_pub_key_attributeTemplateList, wrapping_priv_key_attributeTemplateList);
                System.out.println("Wrapping Key Gen END!");

                KeyPair rsa_keypair = hSession.generateKeyPair(rsagen_mcha, pub_key_attributeTemplateList, priv_key_attributeTemplateList);
                System.out.println("Key Gen END!");
                
                RSAPublicKey RSApublic_wrappingkey = (RSAPublicKey) wrapping_key.getPublicKey();
                RSAPrivateKey RSAPrivateKey = (RSAPrivateKey) rsa_keypair.getPrivateKey();

                // initialize for wrap
                long aes_key_bits = 256;
                Mechanism hash_mcha = Mechanism.get(PKCS11Constants.CKM_SHA256);
                RSAPkcsOaepParameters oaep_params = new RSAPkcsOaepParameters(hash_mcha, PKCS11Constants.CKG_MGF1_SHA256, SourceType.EMPTY, null);
                RsaAesKeyWrapParameters rsaaeswrap_params = new RsaAesKeyWrapParameters(aes_key_bits, oaep_params);
                Mechanism mcha = Mechanism.get(PKCS11Constants.CKM_RSA_AES_KEY_WRAP);
                mcha.setParameters(rsaaeswrap_params);
                
                // Wrap
                byte[] WrappedData = hSession.wrapKey(mcha, RSApublic_wrappingkey, RSAPrivateKey);
                System.out.println("Wrapped Data : ");
                System.out.println(byte2hex(WrappedData));

                hSession.closeSession();
                p11.finalize(null);
                System.out.println("FINISHED\n");

            } catch (PKCS11Exception ee) {
                ee.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String byte2hex(byte bs[]) {
        int i;
        String s = new String();
        String hex_digits = "0123456789ABCDEF";
        byte c;

        if (bs == null || bs.length == 0) {
            return s;
        }

        for (i = 0; i < bs.length; ++i) {
            c = bs[i];
            s += hex_digits.charAt((c >> 4) & 0xf);
            s += hex_digits.charAt(c & 0xf);
        }
        return s;
    }
}
