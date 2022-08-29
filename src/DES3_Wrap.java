import java.io.IOException;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.DES3SecretKey;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

public class DES3_Wrap
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

            //generation DES3 KEY
            //Mechanism mcha = Mechanism.get(PKCS11Constants.CKM_DES3_KEY_GEN);
            byte[] inkey_value = {(byte)0xBC, (byte)0x04, (byte)0xDC, (byte)0x52, (byte)0x97, (byte)0x80, (byte)0x16, (byte)0xE9, 
                (byte)0xDC, (byte)0x31, (byte)0x52, (byte)0x15, (byte)0x91, (byte)0x08, (byte)0xDA, (byte)0xBA, 
                (byte)0x62, (byte)0xD3, (byte)0x49, (byte)0x45, (byte)0xB3, (byte)0x8A, (byte)0x45, (byte)0xF8};

            /* Setup the template for the key. */

            DES3SecretKey key_attributeTemplateList = new DES3SecretKey();
            key_attributeTemplateList.getLabel().setCharArrayValue("DES3_IAIK_KEY".toCharArray());
            key_attributeTemplateList.getKeyType().setLongValue(PKCS11Constants.CKK_DES3);
            key_attributeTemplateList.getDecrypt().setBooleanValue(PKCS11Constants.TRUE);
            key_attributeTemplateList.getEncrypt().setBooleanValue(PKCS11Constants.TRUE);
            key_attributeTemplateList.getWrap().setBooleanValue(PKCS11Constants.TRUE);
            key_attributeTemplateList.getUnwrap().setBooleanValue(PKCS11Constants.TRUE);
            key_attributeTemplateList.getSensitive().setBooleanValue(PKCS11Constants.TRUE);
            key_attributeTemplateList.getToken().setBooleanValue(PKCS11Constants.FALSE);
            key_attributeTemplateList.getPrivate().setBooleanValue(PKCS11Constants.TRUE);
            key_attributeTemplateList.getExtractable().setBooleanValue(PKCS11Constants.TRUE);
            key_attributeTemplateList.getValue().setByteArrayValue(inkey_value);
            
            try
            {
                DES3SecretKey wrappingKey = (DES3SecretKey) hSession.createObject(key_attributeTemplateList);
                System.out.println("Wrapping Key Gen END!");

                DES3SecretKey Key = (DES3SecretKey) hSession.createObject(key_attributeTemplateList);
                System.out.println("Key Gen END!");

                // Wrap()
              
                 // be sure that your token can process the specified mechanism
                Mechanism encryptionMechanism = Mechanism.get(PKCS11Constants.CKM_DES3_CBC_PAD);
                //byte[] encryptInitializationVector = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };  //16byte
                byte[] encryptInitializationVector = { 0, 0, 0, 0, 0, 0, 0, 0};  //8byte
                InitializationVectorParameters encryptInitializationVectorParameters = new InitializationVectorParameters( encryptInitializationVector);
                encryptionMechanism.setParameters(encryptInitializationVectorParameters);

                // initialize for encryption
                hSession.encryptInit(encryptionMechanism, wrappingKey);

                byte[] encryptedData = hSession.encrypt(inkey_value);

                System.out.println(
                    "################################################################################");

                byte[] wrappedKey = hSession.wrapKey(encryptionMechanism, wrappingKey, Key);
                DES3SecretKey keyTemplate = new DES3SecretKey();
                keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
                keyTemplate.getToken().setBooleanValue(PKCS11Constants.FALSE);

                System.out.println("unwrapping key");

                DES3SecretKey unwrappedKey = (DES3SecretKey) hSession.unwrapKey(encryptionMechanism,
                    wrappingKey, wrappedKey, keyTemplate);

                System.out.println(
                    "################################################################################");
                System.out.println("trying to decrypt");

                Mechanism decryptionMechanism = Mechanism.get(PKCS11Constants.CKM_DES3_CBC_PAD);
                //byte[] decryptInitializationVector = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                byte[] decryptInitializationVector = { 0, 0, 0, 0, 0, 0, 0, 0};  //8byte
                InitializationVectorParameters decryptInitializationVectorParameters = new InitializationVectorParameters(
                    decryptInitializationVector);
                decryptionMechanism.setParameters(decryptInitializationVectorParameters);

                // initialize for decryption
                hSession.decryptInit(decryptionMechanism, unwrappedKey);        
                byte[] decryptedData = hSession.decrypt(encryptedData);
                System.out.println("Decrypted Data : "+ byte2hex(decryptedData));
                
                // compare initial data and decrypted data
                boolean equal = false;
                if (inkey_value.length != decryptedData.length) {
                equal = false;
                } 
                else {
                    equal = true;
                    for (int i = 0; i < inkey_value.length; i++) {
                        if (inkey_value[i] != decryptedData[i]) {
                            equal = false;
                            break;
                        }
                    }
                }

                System.out.println((equal) ? "successful" : "ERROR");
                System.out.println(
                    "################################################################################");

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
