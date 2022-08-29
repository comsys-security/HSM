import java.io.IOException;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

public class GenKey_AES
{
    static char[] pin_ocs="comsys2019".toCharArray();
    static String p11_lib_path = "/opt/nfast/toolkits/pkcs11/libcknfast.so";
    static int login_slot = 1;
    public static void main(String[] args) throws TokenException
    {
        try{
            Module p11 = Module.getInstance(p11_lib_path);
            p11.initialize(null);

            Slot[] slots = p11.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);

            if (slots.length == 0) {
                System.out.println("No slot with present token found!");
                throw new TokenException("No token found!");
            }

            for ( int i = 0; i < slots.length; i++ )
            {
                System.out.println("slot name " + i + " :" + slots[i].getSlotInfo().getSlotDescription());
            }
            
            Token token = slots[login_slot].getToken(); /* Get slot ID */
            Session hSession = token.openSession(Token.SessionType.SERIAL_SESSION,
                                                Token.SessionReadWriteBehavior.RW_SESSION,null,null);
                                                hSession.login(Session.UserType.USER,pin_ocs );

            //generation AES KEY
            Mechanism mcha = Mechanism.get(PKCS11Constants.CKM_AES_KEY_GEN);
  
            /* Setup the template for the key. */

            AESSecretKey key_attributeTemplateList = new AESSecretKey();
            key_attributeTemplateList.getLabel().setCharArrayValue("TEST_IAIK_KEY".toCharArray());
            key_attributeTemplateList.getKeyType().setLongValue(PKCS11Constants.CKK_AES);
            key_attributeTemplateList.getDecrypt().setBooleanValue(PKCS11Constants.TRUE);
            key_attributeTemplateList.getEncrypt().setBooleanValue(PKCS11Constants.TRUE);
            key_attributeTemplateList.getWrap().setBooleanValue(PKCS11Constants.TRUE);
            key_attributeTemplateList.getSensitive().setBooleanValue(PKCS11Constants.TRUE);
            key_attributeTemplateList.getToken().setBooleanValue(PKCS11Constants.TRUE);
            key_attributeTemplateList.getPrivate().setBooleanValue(PKCS11Constants.TRUE);
            key_attributeTemplateList.getExtractable().setBooleanValue(PKCS11Constants.TRUE);
            key_attributeTemplateList.getValueLen().setLongValue((long)32);

            try
            {
                AESSecretKey AESKey = (AESSecretKey) hSession.generateKey(mcha,key_attributeTemplateList);
                System.out.println("Key Gen END!");
                
                // Encryption
                byte[] rawData = hSession.generateRandom(64);
                System.out.println("Original Data : " ) ;
                System.out.println( byte2hex( rawData) ) ;

                Mechanism encryptionMechanism = Mechanism.get(PKCS11Constants.CKM_AES_CBC_PAD);
                byte[] encryptInitializationVector = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                InitializationVectorParameters encryptInitializationVectorParameters = new InitializationVectorParameters(encryptInitializationVector);
                encryptionMechanism.setParameters(encryptInitializationVectorParameters);

                // initialize for encryption
                hSession.encryptInit(encryptionMechanism, AESKey);
                byte[] encryptedData = hSession.encrypt(rawData);
                System.out.println("Encrypted  Data : " ) ;
                System.out.println( byte2hex(encryptedData) ) ;
                
                // Decryption
                Mechanism decryptionMechanism = Mechanism.get(PKCS11Constants.CKM_AES_CBC_PAD);
                byte[] decryptInitializationVector = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                InitializationVectorParameters decryptInitializationVectorParameters = new InitializationVectorParameters(decryptInitializationVector);
                decryptionMechanism.setParameters(decryptInitializationVectorParameters);

                // initialize for decryption
                hSession.decryptInit(decryptionMechanism, AESKey);
                byte[] decryptedData = hSession.decrypt(encryptedData);
                System.out.println("Decrypted  Data : " ) ;
                System.out.println( byte2hex(decryptedData) ) ;

                hSession.closeSession();
                p11.finalize(null);
                System.out.println("FINISHED\n");

            }
            catch ( PKCS11Exception ee )
            {
                ee.printStackTrace();
            }
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }
    }
    private static String byte2hex(byte bs[]) {
        int i ;
        String s = new String( ) ;
        String hex_digits = "0123456789ABCDEF";
        byte c ;

        if ( bs == null || bs.length == 0 ) {
                         return s ;
        }

        for ( i = 0 ; i < bs.length; ++i) {
                         c = bs[i] ;
                         s += hex_digits.charAt( ( c >> 4) & 0xf) ;
                         s += hex_digits.charAt( c & 0xf) ;
        }
        return s ;
    }
}
