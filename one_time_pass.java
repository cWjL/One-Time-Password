import java.util.*;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/*
 * Author: 		Jacob Loden
 *  
 * Description:	Program to create and authenticate a one-time password using S/KEY hash chain algorithm.
 * 
 * Installation:		
 * 				Compile:
 * 						-javac one_time_pass.java
 * 				Run Program:
 * 						-java -cp . one_time_pass 
 * Usage:
 * 				Password Generation:
 * 
 * 					User will be presented with the following options:
 *
 *						[A] Enter String to Encode
 *						[B] Get Random String From System
 *
 *						-Selecting 'A' will allow user to enter any string to be used as initial hash chain value (W).
 *				 		-Selecting 'B' will cause the system to generate a random 32 bit string to serve as initial hash chain value (W).
 *
 *					The string value W will be hashed N times (N=5) and stored in the variable "passwordList".
 *
 *					These 5 hashed strings will then be printed in reverse order (N=5, N=4,..., N=1).
 *
 *					User must record the values, N=4, ..., N=1, for authentication.
 *
 *					All but the final hash value, N=5, will be deleted form the variable "passwordList".
 *
 *					This value of "passwordList" will be stored then printed to screen.
 *
 *				Authentication:
 *
 *					After creating the password, subsequent program runs will produce the following options:
 *
 *						[C] Authenticate
 *						[R] Reset Password
 *						[E] Exit
 *
 *						-Selecting option 'C' will produce a prompt to enter the current authentication string (initially N=4).
 *						-Selecting option 'R' will delete the password hash chain on file and reset the process (for use with forgotten password string).
 *						-Selecting option 'E' will exit the current program run without affecting the authentication chain process (if N=3 and 'E' is
 *						 selected, the next run will require the N=3 password).
 *
 * 					Each subsequent run of the program will require the next hashed string the the chain.
 * 
 * 					Successful authentication will result in:
 * 
 * 						$> Access granted!
 * 
 * 						-The next run after a successful authentication will require the next hash in chain
 * 
 * 					Failed authentication will result in:
 * 
 * 						$> Authentication failed!
 * 
 * 						-The next run after a failed authentication will require the current hash in the chain.
 * 						-EX: N=3, wrong N=3 password entered, next run will require N=3 password.
 * 
 * 					Upon successful entry of all four chained hashes, the program will inform user that there are no more passwords to authenticate.
 * 
 * 					The next run after password exhaustion will start the entire process over again.
 * 
 * Notes:
 * 
 * 				During operation, a file named "h_k" containing a text file named "h_txt" is created in the parent project directory.  This text file contains
 * 				the current authentication string.  IT MUST BE ALLOWED TO REMAIN FOR THE DURATION OF THE HASH CHAIN PROCESS.
 * 
 * 				The file will be automatically deleted when:
 * 
 * 					-All passwords have been used
 * 					-The 'R' option is selected after creating a password
 */

/*
 * @param none
 * @return none
 * @author Jacob Loden
 */
class G_hashed_key {
	
	private static final String BASE_PATH = "h_k";
	private Path h_txt, h_file;
	private boolean file_ex;
	
	/*
	 * @param none
	 * @return none
	 * 
	 * Class constructor
	 */
	public G_hashed_key(){
		h_file = Paths.get(BASE_PATH);
		File f = new File("h_k/h_k_t.txt");
		if(!f.exists() && !f.isDirectory()){
			try{
				file_ex = new File(BASE_PATH).mkdir();
			}catch(SecurityException ex){
				System.out.println(ex.getMessage());
			}
			file_ex = false;
		}else{
			file_ex = true;
		}
		
		this.h_txt = Paths.get("h_k/h_k_t.txt");
	}
	
	/*
	 * @param none
	 * @return boolean: return true if file already exists
	 * 
	 * Check if file exists
	 */
	public boolean check_file(){
		return file_ex;
	}
	
	/*
	 * @param none
	 * @return Path:  path to created file
	 * 
	 * Get file path
	 */
	public Path g_file(){
		return this.h_txt;
	}
	
	/*
	 * @param String w: hashed password string to write to file
	 * @return none
	 * 
	 * Store string in file
	 */
	public void s_file(String w){
		Vector<String> tmp = new Vector<String>();
		tmp.add(w);
		
		try {
			Files.write(this.h_txt, tmp, Charset.forName("UTF-8"));
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}
	}
	
	/*
	 * @param none
	 * @return String: hashed password string from file
	 * 
	 * Read line from file
	 */
	public String g_file_text() throws IOException{
		return new String(Files.readAllBytes(h_txt));
	}
	
	/*
	 * @param none
	 * @return none
	 * 
	 * Delete file
	 */
	public void del_file() throws IOException{;
		Files.delete(h_txt);
		Files.delete(h_file);
	}
}

/*
 * @param none
 * @return none
 * @author Jacob Loden, ID 1204452387, CSE465, Spring 2017
 */
public class one_time_pass {
	
	private static final int N = 5;
	private Vector<String> passwordList;
	private String NEXT_STR_W;
	private G_hashed_key key_ops;
	private int itr;
	
	/*
	 * @param none
	 * @return none
	 * 
	 * Class constructor
	 */
	public one_time_pass(){
		key_ops = new G_hashed_key();
		this.NEXT_STR_W = "";
		this.passwordList = new Vector<String>();
	}
	
	/*
	 * @param none
	 * @return none
	 * 
	 * Check for the existence of password file
	 */
	public boolean check_for_file(){
		return key_ops.check_file();
	}
	
	/*
	 * @param none
	 * @return none
	 * 
	 * Check if all passwords have been used
	 */
	public boolean check_itr(){
		return (itr == 0);
	}
	
	/*
	 * @param String w: Password string to hash
	 * @return none
	 * @throws NoSuchAlgorithmException, UnsupportedEncodingException
	 * 
	 * Generate hashed string value
	 */
	public void gen_hash(String w, boolean loop) throws NoSuchAlgorithmException, UnsupportedEncodingException{
		MessageDigest md = MessageDigest.getInstance("MD5");
		BigInteger b_int;
		if(loop){
			for(int i = 0; i < N; i++){
				byte[] b = w.getBytes(Charset.forName("UTF-8"));
				md.update(b);
				byte[] digest = md.digest();
				b_int = new BigInteger(1, digest);
				w = b_int.toString();
				passwordList.add(w);
			}
			key_ops.s_file((passwordList.size()-1) + passwordList.elementAt(N-1)); // write hash vec to file
		}else{
			byte[] b = w.getBytes(Charset.forName("UTF-8"));
			md.update(b);
			byte[] digest = md.digest();
			b_int = new BigInteger(1, digest);
			NEXT_STR_W = b_int.toString();
		}
	}
	
	/*
	 * @param String auth: Password string to hash
	 * @return String:  Hashed value of string auth
	 * @throws NoSuchAlgorithmException, UnsupportedEncodingException
	 * 
	 * Generate hashed string value
	 */
	public String gen_hash_on_demand(String auth) throws NoSuchAlgorithmException{
		MessageDigest md = MessageDigest.getInstance("MD5");
		BigInteger b_int;
		
		byte[] b = auth.getBytes(Charset.forName("UTF-8"));
		md.update(b);
		byte[] digest = md.digest();
		b_int = new BigInteger(1, digest);
		
		return b_int.toString();
	}
	
	

	/*
	 * @param none
	 * @return String: Randomly generated password string
	 * 
	 * Generate random initial string w
	 */
	public String get_random_w(){
		String new_w = "";
		String alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
		Random rand = new Random();
		
		for(int i = 0; i < 32; i++){
			new_w = new_w + alpha.charAt(rand.nextInt(alpha.length()));
		}
		//System.out.println(new_w);
		return new_w;
	}
	
	/*
	 * @param none
	 * @return String:  User selected option
	 * 
	 * Print authentication option welcome screen
	 */
	public String print_auth_welcome(boolean welcome){
		Scanner keyboard = new Scanner(System.in);
		String usr = "";
		if(welcome){
			for(int i = 0; i < 154; i++){
				System.out.print('*');
				if(i==76){
					System.out.println();
				}
			}
			System.out.print("\n\n");
			System.out.println("*****" + "\t\t" + "S/KEY Generation and Authentication" + "\t\t\t" + "*****" + "\n");
			for(int i = 0; i < 154; i++){
				System.out.print('*');
				if(i==76){
					System.out.println();
				}
			}
			System.out.println();
			
			System.out.println("One-Time use password found on file!\n");
		}
		System.out.println("Make selection:");
		System.out.println();
		System.out.println("\t" + "[C] Authenticate");
		System.out.println("\t" + "[R] Reset Password");
		System.out.println("\t" + "[E] Exit");
		System.out.println();
		System.out.print("\t$> ");
		
		usr = keyboard.next();
		
		if(usr.toUpperCase().equals("C") || usr.toUpperCase().equals("R") || usr.toUpperCase().equals("E")){
			return usr;
		}else{
			return "";
		}
	}
	
	/*
	 * @param none
	 * @return String:  User selected option
	 * 
	 * Print initial welcome screen
	 */
	public String print_welcome(){
		Scanner keyboard = new Scanner(System.in);
		String usr = "";
		
		for(int i = 0; i < 154; i++){
			System.out.print('*');
			if(i==76){
				System.out.println();
			}
		}
		System.out.print("\n\n");
		System.out.println("*****" + "\t\t" + "S/KEY Generation and Authentication" + "\t\t\t" + "*****" + "\n");
		for(int i = 0; i < 154; i++){
			System.out.print('*');
			if(i==76){
				System.out.println();
			}
		}
		System.out.println();
		
		System.out.println("Make selection:");
		System.out.println();
		System.out.println("\t" + "[A] Enter String to Encode");
		System.out.println("\t" + "[B] Get Random String From System");
		System.out.println();
		System.out.print("\t$> ");
		
		usr = keyboard.next();
		
		if(usr.toUpperCase().equals("A") || usr.toUpperCase().equals("B") || usr.toUpperCase().equals("C")){
			return usr;
		}else{
			return "";
		}
	}
	
	/*
	 * @param String:  User supplied hashed password string to authenticate
	 * @return none
	 * 
	 * Check authentication string supplied by user against string stored in file
	 */
	public int authenticate(String n_1) throws IOException, NoSuchAlgorithmException{
		String server_str = key_ops.g_file_text();
		itr = Character.getNumericValue(server_str.charAt(0));
		server_str = server_str.substring(1, server_str.length()-1); //remove newline char
		passwordList.add(server_str);
		gen_hash(n_1, false);
		if(server_str.equals(NEXT_STR_W)){
			itr--;
			key_ops.s_file(itr + n_1);
			return 0;
		}else{
			return -1;
		}
	}
	
	/*
	 * @param none
	 * @return none
	 * 
	 * Prints list in reverse order
	 */
	public void print_hash_lst(){
		if(passwordList.size() > 1){
			for(int i = passwordList.size()-1; i >= 0; i--){
				System.out.println("\t$> " + passwordList.elementAt(i));
			}
		}else{
			System.out.println("\t$> " + passwordList.elementAt(0));
		}
	}

	/*
	 * @param none
	 * @return none
	 * 
	 * Clear passwordList
	 */
	public void clear_list(){
		System.out.println("\t$> Deleting All but last authentication string...");
		int size = passwordList.size()-1;
		pause_exec();
		for(int i = 0; i < size; i++){
			passwordList.remove(0);
		}
	}
	
	/*
	 * @param none
	 * @return none
	 * 
	 * Pause execution
	 */
	public void pause_exec(){
		try {
			Thread.sleep(2000);
		} catch (InterruptedException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
	}
	
	/*
	 * @param none
	 * @return returns user supplied password
	 * 
	 * Get user supplied initial string w
	 */
	public String get_w(){
		Scanner keyboard = new Scanner(System.in);
		String tmp = "";
		System.out.print("\t$> Enter password to store: ");
		
		tmp = keyboard.next();
		return tmp;
	}
	
	/*
	 * @param none
	 * @return returns user supplied authentication string
	 * 
	 * Get authentication string from user
	 */
	public String get_auth(){
		Scanner keyboard = new Scanner(System.in);
		String tmp = "";
		System.out.print("\t$> Enter authentication: ");
		
		tmp = keyboard.next();
		return tmp;
	}
	
	/*
	 * @param none
	 * @return none
	 * 
	 * Delete password file
	 */
	public void file_del() throws IOException{
		key_ops.del_file();
	}
	
	/*
	 * @param none
	 * @return none
	 * 
	 * Display command line argument usage
	 */
	public void usage(){
		System.out.println("\tCommand line argument usage:");
		System.out.println("\tcse465_1204452387.java A <new_password_string>");
		System.out.println("\tcse465_1204452387.java B");
		System.out.println("\tcse465_1204452387.java C <password_string>");
		System.exit(0);
	}
	
	/*
	 * @param none, or two command line arguments: <option> and either <new_password> or <password>
	 * @return none
	 */
	public static void main(String[] argv){
		String opt = "";
		String w = "";
		String auth = "";
		one_time_pass run = new one_time_pass();
		
		if(!run.check_for_file()){
			if(argv.length > 0){
				if(argv[0].toUpperCase().equals("A") && argv.length > 1){
					w = argv[1];
				}else if(argv[0].toUpperCase().equals("B")){
					w = run.get_random_w();
				}else if(argv[0].toUpperCase().equals("C")){
					System.out.println("\t$> You must create a one time password before you can authenticate!");
					System.exit(0);
				}else{
					run.usage();
				}
			}else{
				opt = run.print_welcome();
				if(opt.toUpperCase().equals("A")){
					w = run.get_w();
				}else if(opt.toUpperCase().equals("B")){
					w = run.get_random_w();
				}else{
					System.out.println("\t$> Valid arguments are:  A: Provide your own password, B: System generated password");
					try {
						run.file_del();
					} catch (IOException e) {
						System.out.println(e.getMessage());
						e.printStackTrace();
					}
					System.exit(0);
				}
			}
			System.out.println("\t$> Initial Secret: " + w);
			System.out.println("\t$> Beginning Hashing...");
			run.pause_exec();

			try {
				run.gen_hash(w, true);
			} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
				System.out.println(e.getMessage());
				e.printStackTrace();
			}
			run.pause_exec();
			System.out.println("\t$> Ensure list is recorded in the EXACT ORDER printed.  Keep list in a safe place!");
			run.print_hash_lst();
			run.clear_list();
			System.out.println("\t$> Storing authentication string...");
			run.pause_exec();
			System.out.println("\t$> Printing stored hashed string...");
			run.print_hash_lst();
		}else{
			if(argv.length > 0){
				if(!argv[0].toUpperCase().equals("C")){
					System.out.println("\t$> You have already created a password!  You must authenticate!");
					System.exit(0);
				}else{
					auth = argv[1];
				}
			}else{
				opt = run.print_auth_welcome(true);
				if(opt.toUpperCase().equals("E")){
					System.out.println("\t$> Goodbye");
					System.exit(0);
				}else if(opt.toUpperCase().equals("R")){
					try {
						run.file_del();
					} catch (IOException e) {
						System.out.println(e.getMessage());
						e.printStackTrace();
					}
					System.out.println("\t$> Password file reset!");
					System.exit(0);
				}else if(opt.toUpperCase().equals("C")){
					auth = run.get_auth();
				}else{
					System.out.println("\t$> Valid arguments are:  C: Authenticate, R: Reset system password, E: Exit");
					System.exit(0);
				}
			}
			int good = -1;
			try{
				good = run.authenticate(auth);
			}catch(IOException | NoSuchAlgorithmException e){
				System.out.println(e.getMessage());
				e.printStackTrace();
			}catch(NullPointerException ne){
				ne.printStackTrace();
			}
			if(good != 0){
				System.out.println("\t$> Password incorrect!");
				System.out.println("\t$> Goodbye");
				System.exit(0);
			}else{
				System.out.println("\t$> Password entered:");
				System.out.println("\t$> " + auth);
				System.out.println("\t$> Hashed value:");
				try {
					System.out.println("\t$> " + run.gen_hash_on_demand(auth));
				} catch (NoSuchAlgorithmException e) {
					System.out.println(e.getMessage());
					e.printStackTrace();
				}
				System.out.println("\t$> Current Password:");
				run.print_hash_lst();
				System.out.println("\t$> Access granted!");
				System.out.println("\t$> ");
				run.pause_exec();
			}
			if(run.check_itr()){
				try {
					run.file_del();
				} catch (IOException e) {
					e.printStackTrace();
				}
				System.out.println("\t$> All one-time passwords have been exhausted");
				System.exit(0);
			}
		}	
		System.exit(0);
	}

}
