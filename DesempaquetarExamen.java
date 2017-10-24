 /* Agumentos:
 * 0 -> nombre de paquete
 * 1 -> fichero del examen (nombre que le quieres poner)
 * 2 -> fichero de la clave privada del profesor
 * 3 -> fichero de la clave publica de la autoridad
 * 4 -> fichero de la clave publica del alumno
 */

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.io.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

public class DesempaquetarExamen {
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider()); //cargar el provider BC
		SecretKeyFactory secretKeyFactoryDES = SecretKeyFactory.getInstance("DES");
		KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
		
		Paquete paquete=PaqueteDAO.leerPaquete(args[0]);
		if(paquete!=null) System.out.println("Paquete recibido: "+paquete.toString());
		
		byte[] examenCifrado=paquete.getContenidoBloque("Examen");
		if(examenCifrado==null) System.err.print("\nERROR: No existe el bloque del examen");
		byte[] claveCifrada=paquete.getContenidoBloque("ClaveDES");
		if(claveCifrada==null) System.err.print("\nERROR: No existe el bloque de la clave DES");
		byte[] firma=paquete.getContenidoBloque("Firma");
		if(firma==null) System.err.print("\nERROR: No existe el bloque de la firma");
		byte[] fecha=paquete.getContenidoBloque("Fecha");
		if(fecha==null) System.err.print("\nERROR: No existe el bloque de la fecha");
		byte[] sello=paquete.getContenidoBloque("Sello");
		if(sello==null) System.err.print("\nERROR: No existe el bloque del sello");
		
		//obtenemos la claves publicas y privadas
		File ficheroPrivateKey=new File(args[2]);
		int tamanoFicheroPrivateKey = (int) ficheroPrivateKey.length();
		byte[] bufferPrivateKey = new byte[tamanoFicheroPrivateKey];
		FileInputStream in = new FileInputStream(ficheroPrivateKey);
		in.read(bufferPrivateKey, 0, tamanoFicheroPrivateKey);
		in.close();
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bufferPrivateKey);
		PrivateKey privateKeyProfe = keyFactoryRSA.generatePrivate(privateKeySpec);
		
		File ficheroPublicKeyAuto=new File(args[3]);
		int tamanoFicheroPublicKeyAuto = (int) ficheroPublicKeyAuto.length();
		byte[] bufferPublicKeyAuto = new byte[tamanoFicheroPublicKeyAuto];
		in = new FileInputStream(ficheroPublicKeyAuto);
		in.read(bufferPublicKeyAuto, 0, tamanoFicheroPublicKeyAuto);
		in.close();
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bufferPublicKeyAuto);
		PublicKey publicKeyAuto = keyFactoryRSA.generatePublic(publicKeySpec); //clave publica autoridad
		
		File ficheroPublicKeyAlum=new File(args[4]);
		int tamanoFicheroPublicKeyAlum = (int) ficheroPublicKeyAlum.length();
		byte[] bufferPublicKeyAlum = new byte[tamanoFicheroPublicKeyAlum];
		in = new FileInputStream(ficheroPublicKeyAlum);
		in.read(bufferPublicKeyAlum, 0, tamanoFicheroPublicKeyAlum);
		in.close();
		publicKeySpec = new X509EncodedKeySpec(bufferPublicKeyAlum);
		PublicKey publicKeyAlum = keyFactoryRSA.generatePublic(publicKeySpec); //clave publica alumno
		
		//desciframos el sello
		Cipher cifrador = Cipher.getInstance("RSA", "BC");
		//cifrador.init(Cipher.ENCRYPT_MODE, publicKeyAuto);
		cifrador.init(Cipher.DECRYPT_MODE, publicKeyAuto);
		byte[] selloRoto = cifrador.doFinal(sello); //hash de firma + fecha recibido en paquete
		
		MessageDigest messageDigest = MessageDigest.getInstance("SHA"); //Crear funcion resumen
		messageDigest.update(firma, 0, firma.length);
		messageDigest.update(fecha, 0, fecha.length);
		byte[] resumenSello = messageDigest.digest(); //hash de firma + fecha (hecho aqui)
		
		//comprobamos sello de autoridad
		if(Arrays.areEqual(resumenSello,selloRoto)) System.out.println("Sello de autoridad: COMFIRMADO");
		else System.err.print("\nERROR: confirmacion de sello de autoridad fallido\n - Hash recibido: "+selloRoto.toString()+"\n - Hash calculado: "+resumenSello.toString());
		
		//descriframos la clave DES
		cifrador.init(Cipher.DECRYPT_MODE, privateKeyProfe);
		byte[] bufferClaveDES = cifrador.doFinal(claveCifrada);
		DESKeySpec DESspec = new DESKeySpec(bufferClaveDES);
		SecretKey claveDES = secretKeyFactoryDES.generateSecret(DESspec);
		
		Cipher cifrador2=Cipher.getInstance("DES/ECB/PKCS5Padding");
		cifrador2.init(Cipher.DECRYPT_MODE, claveDES);
		byte[] examen = cifrador2.doFinal(examenCifrado); //examen descifrado en byte
		
		messageDigest = MessageDigest.getInstance("SHA"); //Crear funcion resumen
		messageDigest.update(examen, 0, examen.length);
		byte[] resumenExamen = messageDigest.digest(); //hash de examen (hecho aqui)
		
		//descriframos la firma
		cifrador.init(Cipher.DECRYPT_MODE, publicKeyAlum);
		byte[] resumenFirma = cifrador.doFinal(firma); //resumen del examen recibido
		
		//comprobamos sello de autoridad
		if(Arrays.areEqual(resumenFirma,resumenExamen)) System.out.println("Firma de alumno: COMFIRMADA");
		else System.err.print("\nERROR: confirmacion de firma de alumno fallida\n - Hash recibido: "+resumenFirma.toString()+"\n - Hash calculado: "+resumenExamen.toString());
		
		//Extraemos el examen
		FileOutputStream out = new FileOutputStream(args[1]);
		out.write(examen); // Escribir texto cifrado
		out.close();
	}
}
