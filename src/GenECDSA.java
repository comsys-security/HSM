import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import iaik.pkcs.pkcs11.InitializeArgs;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import iaik.pkcs.pkcs11.objects.ECDSAPrivateKey;
import iaik.pkcs.pkcs11.objects.ECDSAPublicKey;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.DefaultInitializeArgs;
import iaik.pkcs.pkcs11.DefaultMutexHandler;

public class GenECDSA
{
    static BufferedReader input_;

    static PrintWriter output_;
  
    static {
      try {
        output_ = new PrintWriter(System.out, true);
        input_ = new BufferedReader(new InputStreamReader(System.in));
      } catch (Throwable thr) {
        thr.printStackTrace();
        output_ = new PrintWriter(System.out, true);
        input_ = new BufferedReader(new InputStreamReader(System.in));
      }
    }
    
    static char[] pin_ocs="comsys2019".toCharArray();
    static String p11_lib_path = "/opt/nfast/toolkits/pkcs11/libcknfast.so";
    static int login_slot = 1;
    public static void main(String[] args) throws TokenException, NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        try{
            Module p11 = Module.getInstance(p11_lib_path);
            InitializeArgs initArgs = new DefaultInitializeArgs(new DefaultMutexHandler(),false, true);
            p11.initialize(initArgs);

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

            //generation EC KEY
            Mechanism mcha = Mechanism.get(PKCS11Constants.CKM_EC_KEY_PAIR_GEN);
  
            /* Setup the template for the Private key. */
            byte s_prime256v1[] = { (byte) 0x06, (byte) 0x08, (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0xCE, (byte) 0x3D, (byte) 0x03, (byte) 0x01, (byte) 0x07 };

            ECDSAPrivateKey privkey_attributeTemplateList = new ECDSAPrivateKey();
            privkey_attributeTemplateList.getLabel().setCharArrayValue("TEST_IAIK_ECDSA_KEY".toCharArray());
            privkey_attributeTemplateList.getKeyType().setLongValue(PKCS11Constants.CKK_EC);
            privkey_attributeTemplateList.getDecrypt().setBooleanValue(PKCS11Constants.TRUE);
            privkey_attributeTemplateList.getSensitive().setBooleanValue(PKCS11Constants.TRUE);
            privkey_attributeTemplateList.getToken().setBooleanValue(PKCS11Constants.TRUE);
            privkey_attributeTemplateList.getPrivate().setBooleanValue(PKCS11Constants.TRUE);
            privkey_attributeTemplateList.getExtractable().setBooleanValue(PKCS11Constants.TRUE);
            privkey_attributeTemplateList.getSign().setBooleanValue(Boolean.TRUE);

            /* Setup the template for the Public key. */
            ECDSAPublicKey pubkey_attributeTemplateList = new ECDSAPublicKey();
            pubkey_attributeTemplateList.getEcdsaParams().setByteArrayValue(s_prime256v1);
            pubkey_attributeTemplateList.getLabel().setCharArrayValue("TEST_IAIK_ECDSA_KEY".toCharArray());
            pubkey_attributeTemplateList.getKeyType().setLongValue(PKCS11Constants.CKK_EC);
            pubkey_attributeTemplateList.getToken().setBooleanValue(PKCS11Constants.FALSE);
            pubkey_attributeTemplateList.getPrivate().setBooleanValue(PKCS11Constants.TRUE);
            pubkey_attributeTemplateList.getVerify().setBooleanValue(Boolean.TRUE);

            /* Generate Key */
            KeyPair generatedKeyPair = hSession.generateKeyPair(mcha,pubkey_attributeTemplateList, privkey_attributeTemplateList);

            try
            {
                ECDSAPublicKey ecPublicKey = (ECDSAPublicKey) generatedKeyPair.getPublicKey();
                ECDSAPrivateKey ecPrivateKey = (ECDSAPrivateKey) generatedKeyPair.getPrivateKey();
                
                /* Sign */ 
                System.out.println("Success");
                System.out.println("The public key is");
                System.out.println(
                    "_______________________________________________________________________________");
                    System.out.println(ecPublicKey);
                    System.out.println(
                    "_______________________________________________________________________________");
                System.out.println("The private key is");
                System.out.println(
                    "_______________________________________________________________________________");
                System.out.println(ecPrivateKey);
                System.out.println(
                    "_______________________________________________________________________________");

                System.out.println(
                    "################################################################################");
                System.out.println("Signing Data... ");

                Mechanism signatureMechanism = Mechanism.get(PKCS11Constants.CKM_ECDSA_SHA1);
                hSession.signInit(signatureMechanism, ecPrivateKey);
                byte[] dataToBeSigned = "12345678901234567890123456789012345".getBytes("ASCII");
                byte[] signatureValue = hSession.sign(dataToBeSigned);
                System.out.println("Signature Value: " + Functions.toHexString(signatureValue));
                System.out.println(
                    "################################################################################");

                /* Verifiy */ 
                System.out.println(
                    "################################################################################");
                System.out.println("Verifiy Signature... ");
                Mechanism verificationMechanism = Mechanism.get(PKCS11Constants.CKM_ECDSA_SHA1);
                // initialize for signing
                hSession.verifyInit(verificationMechanism, ecPublicKey);
          
                try {
                    hSession.verify(dataToBeSigned, signatureValue); // throws an exception upon unsuccessful
                                                              // verification
                  System.out.println("Verified the signature successfully");
                } catch (TokenException ex) {
                  System.out.println("Verification FAILED: " + ex.getMessage());
                }
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
}
