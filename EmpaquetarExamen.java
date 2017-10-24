/* Agumentos:
 * 0 -> fichero del examen
 * 1 -> nombre de paquete a crear
 * 2 -> fichero de la clave publica del profesor
 * 3 -> fichero de la clave privada del alumno
 */

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;
import java.io.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

class EmpaquetarExamen{

	public static void main(String[] args) throws Exception{
		Security.addProvider(new BouncyCastleProvider()); // Cargar el provider BC
		
		//generamos la clave sincrona DES
		KeyGenerator generadorDES=KeyGenerator.getInstance("DES");
		generadorDES.init(56); // clave de 56 bits
		SecretKey claveDES=generadorDES.generateKey();

		//leemos archivo a cifrar y lo metemos en un buffer (archivo pequeño)        
		File ficheroExamen=new File(args[0]);
		int tamanoExamen=(int) ficheroExamen.length();
		byte[] bufferExamen=new byte[tamanoExamen];
		FileInputStream in=new FileInputStream(ficheroExamen);
		in.read(bufferExamen,0,tamanoExamen);
		in.close();
		
		/*instanciamos el cifrador:
		algoritmo DES
		modo : ECB (Electronic Code Book)
		relleno : PKCS5Padding*/
		Cipher cifrador=Cipher.getInstance("DES/ECB/PKCS5Padding");
		cifrador.init(Cipher.ENCRYPT_MODE,claveDES); //iniciamos el cifrador en modo encriptador
		
		//ciframos el buffer del examen
		byte[] examenCifrado = cifrador.update(bufferExamen,0,tamanoExamen);
		//byte[] examenCifrado = cifrador.doFinal(); // Completar cifrado (procesa relleno, puede devolver texto) (NO VAAAAAAAAAAAAAAAAAAA)

		/*//COMPROBACION
		FileOutputStream out = new FileOutputStream(args[0]+".cifrado"); 
		out.write(examenCifrado); // Escribir texto cifrado
		out.close();*/
		
		//ciframos la clave DES en RSA
		// Anadir provider JCE (provider por defecto no soporta RSA)
		byte[] bufferClaveDES=claveDES.getEncoded(); //pasa al buffer la claveDES
		
		File ficheroPublicKeyP=new File(args[2]); //cargamos archivo de la clave publica del profesor
		int tamanoFicheroPublicKeyP = (int) ficheroPublicKeyP.length();
		byte[] bufferPublicKeyP = new byte[tamanoFicheroPublicKeyP];
		in = new FileInputStream(ficheroPublicKeyP);
		in.read(bufferPublicKeyP, 0, tamanoFicheroPublicKeyP); //introducimos en un buffer la clave publica del profesor
		in.close();
		
		KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
		
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bufferPublicKeyP);
		PublicKey publicKeyP = keyFactoryRSA.generatePublic(publicKeySpec); //lo pasamos al tipo PublicKey
		cifrador = Cipher.getInstance("RSA", "BC"); // Hace uso del provider BC
		
		/************************************************************************
		* IMPORTANTE: En BouncyCastle el algoritmo RSA no funciona realmente en modo ECB
		*		  * No divide el mensaje de entrada en bloques
		*         * Solo cifra los primeros 512 bits (tam. clave)
		*		  * Si fuera necesario cifrar mensajes mayores (no suele 
		*            serlo al usar "cifrado hibrido"), habrÃ­a que hacer la 
		*            divisiÃ³n en bloques "a mano"
		************************************************************************/
		cifrador.init(Cipher.ENCRYPT_MODE, publicKeyP);  // Cifra con la clave publica del profsor
		byte[] claveCifrada = cifrador.doFinal(bufferClaveDES); //ciframos la clave DES con la clave publica del profesor
		
		/*//COMPROBACION
		out = new FileOutputStream("ClaveDES.cifrado");
		out.write(claveCifrada); // Escribir texto cifrado
		out.close();*/
		
		//Creamos la firma
		MessageDigest messageDigest = MessageDigest.getInstance("SHA"); //Crear funcion resumen
		messageDigest.update(bufferExamen, 0, tamanoExamen);
		byte[] resumen = messageDigest.digest();
		
		File ficheroPrivateKeyA=new File(args[3]); //cargamos archivo de la clave privada del alumno
		int tamanoFicheroPrivateKeyA = (int) ficheroPrivateKeyA.length();
		byte[] bufferPrivateKeyA = new byte[tamanoFicheroPrivateKeyA];
		in = new FileInputStream(ficheroPrivateKeyA);
		in.read(bufferPrivateKeyA, 0, tamanoFicheroPrivateKeyA); //introducimos en un buffer la clave privada del alumno
		in.close();
		
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bufferPrivateKeyA);
		PrivateKey privateKeyA = keyFactoryRSA.generatePrivate(privateKeySpec);
		
		cifrador.init(Cipher.ENCRYPT_MODE, privateKeyA);  // Cifra con la clave privada del alumno
		byte[] firma = cifrador.doFinal(resumen); //ciframos el hash con la clave privada del alumno
		
		/*//COMPROBACION
		out = new FileOutputStream("Firma");
		out.write(firma); // Escribir texto cifrado
		out.close();*/
		
		//creamos los bloques
		Bloque bloqueExamen=new Bloque("Examen",examenCifrado);
		System.out.println("Bloque creado: "+bloqueExamen.toString());
		Bloque bloqueClave=new Bloque("ClaveDES",claveCifrada);
		System.out.println("Bloque creado: "+bloqueClave.toString());
		Bloque bloqueFirma=new Bloque("Firma",firma);
		System.out.println("Bloque creado: "+bloqueFirma.toString());
		
		//creamos el paquete
		Paquete paquete=new Paquete();
		paquete.anadirBloque(bloqueExamen);
		paquete.anadirBloque(bloqueClave);
		paquete.anadirBloque(bloqueFirma);
		System.out.println("Paquete creado: "+paquete.toString());
		
		PaqueteDAO.escribirPaquete(args[1]+".bin", paquete);
	}
}
