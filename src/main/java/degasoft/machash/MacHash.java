package degasoft.machash;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.Vector;

public class MacHash
{
	private static Vector<byte[]> hashes = new Vector<byte[]>();
	private static Vector<String> str_hashes = new Vector<String>();
	private static String xored_hash_string = new String();
	private static byte[] xored_hash_bytes;

	/**
	 * Initializes system and generates hashes from network adapters mac addresses
	 */
	public static void generateHash()
	{
		try
		{
			Enumeration<NetworkInterface> net = NetworkInterface.getNetworkInterfaces();
			while (net.hasMoreElements())
			{
				// Get network interfaces
				NetworkInterface ni = net.nextElement();

				// Get mac address
				byte[] hardwareAddress = ni.getHardwareAddress();

				// Skip loopback and virtual interfaces
				if (ni.isLoopback() || ni.isVirtual()) continue;
	
				// Create Message Digest algorithm
				final MessageDigest digest = MessageDigest.getInstance("SHA3-512");
				
				// Generate Hash from mac address
				final byte[] hash = digest.digest(hardwareAddress);

				// Add hash to vector
				hashes.add(hash);
	
				// DEBUG: print mac addresses in hex format
				for (int i = 0; i < hardwareAddress.length; i++)
				{
					System.out.print(String.format("%02X%s", hardwareAddress[i], (i < hardwareAddress.length - 1) ? "-" : ""));
				}
				System.out.println();
			}

			// Generate hex hash string 
			for (byte[] bhash: hashes)
			{
				final StringBuilder hexString = new StringBuilder();
				for (int i = 0; i < bhash.length; i++)
				{
					final String hex = Integer.toHexString(0xff & bhash[i]);
					if(hex.length() == 1) 
						hexString.append('0');
					hexString.append(hex);
				}
				str_hashes.add(hexString.toString());

				// DEBUG: hash hex representation
				System.out.println(hexString.toString());
			}

			// Xor all hashes in vector
			XorHashes();
		} catch (SocketException e) {
			System.out.println(e.getStackTrace());
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getStackTrace());
		}
	}

	/**
	 * Support function that makes bitwise xor from hashes byte arrays
	 */
	private static void XorHashes()
	{
		int len = hashes.get(0).length;
		byte[] xored_hash_bytes = new byte[len];

		for (int i = 0; i < hashes.size(); i++)
		{
			byte[] hash = hashes.get(i);
			for (int j = 0; j < len; j++)
			{
				xored_hash_bytes[j] = (byte) (xored_hash_bytes[j] ^ hash[j]);
			}
		}

		// Generate hex hash string 
		final StringBuilder hexString = new StringBuilder();
		for (int i = 0; i < xored_hash_bytes.length; i++)
		{
			final String hex = Integer.toHexString(0xff & xored_hash_bytes[i]);
			if(hex.length() == 1) 
				hexString.append('0');
			hexString.append(hex);
		}
		xored_hash_string = hexString.toString();
		
		// DEBUG: hash hex representation
		System.out.println(hexString.toString());
	}

	
	/** 
	 * Return license key in byte array form
	 * @return byte[]
	 */
	public static byte[] getLicenseKeyBytes()
	{
		return xored_hash_bytes;
	}

	
	/** 
	 * Return license key in hex string form
	 * @return String
	 */
	public static String getLicenseKeyString()
	{
		return xored_hash_string;
	}

	
	public static void main (String[] args) throws Exception
	{
		generateHash();
		System.out.println(getLicenseKeyString());
	}
}