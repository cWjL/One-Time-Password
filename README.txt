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
