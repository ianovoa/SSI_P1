/* Agumentos:
 * 0 -> nombre de paquete
 * 1 -> fichero de la clave privada de la autoridad
 */

import java.util.Date;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;
import java.io.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SellarExamen {
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider()); //cargar el provider BC
		KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
		
		Paquete paquete=PaqueteDAO.leerPaquete(args[0]);
		if(paquete!=null) System.out.println("Paquete recibido: "+paquete.toString());
		byte[] firma=paquete.getContenidoBloque("Firma");
		if(firma==null) System.err.print("\nERROR: No existe el bloque de la firma digital");
		
		byte[] fecha = new Date().toString().getBytes(); //fecha actual del sistema
		
		MessageDigest messageDigest = MessageDigest.getInstance("SHA"); //Crear funcion resumen
		messageDigest.update(firma, 0, firma.length);
		messageDigest.update(fecha, 0, fecha.length);
		byte[] resumen = messageDigest.digest(); //hash de firma + fecha
		
		File ficheroPrivateKey=new File(args[1]); //cargamos archivo de la clave privada de la autoridad
		int tamanoFicheroPrivateKey = (int) ficheroPrivateKey.length();
		byte[] bufferPrivateKey = new byte[tamanoFicheroPrivateKey];
		FileInputStream in = new FileInputStream(ficheroPrivateKey);
		in.read(bufferPrivateKey, 0, tamanoFicheroPrivateKey); //introducimos en un buffer la clave privada de la autoridad
		in.close();
		
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bufferPrivateKey);
		PrivateKey privateKey = keyFactoryRSA.generatePrivate(privateKeySpec);
		
		Cipher cifrador = Cipher.getInstance("RSA", "BC");
		cifrador.init(Cipher.ENCRYPT_MODE, privateKey);  // Cifra con la clave privada de la autoridad
		byte[] sello = cifrador.doFinal(resumen);
		
		Bloque bloqueFecha=new Bloque("Fecha",fecha);
		System.out.println("Bloque creado: "+bloqueFecha.toString());
		Bloque bloqueSello=new Bloque("Sello",sello);
		System.out.println("Bloque creado: "+bloqueSello.toString());
		
		paquete.anadirBloque(bloqueFecha);
		paquete.anadirBloque(bloqueSello);
		System.out.println("Paquete sellado: "+paquete.toString());
		
		PaqueteDAO.escribirPaquete(args[0], paquete);
	}
}
