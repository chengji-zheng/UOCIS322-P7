# UOCIS322 - Project 7 #
Adding authentication and user interface to brevet time calculator service. The complete versoion of brevets APP.


### Author: Chengji Zheng           ### E-mail: chengjiz@uoregon.edu


### Changes
##### 1. Added User Login / Creat Account functions on the client side.
##### 2. Added User Login / Create Account function on the backend too. (1) For `create account`, it takes the user name and password and check if the username is duplicate, if not, then hashed the password and put them into the database. (2) For `login`, it takes the username and encrypted password (for security reason) to the backend, see if they are matched or not. If matched, then returns a success message and refirect the user to the correct page. Otherwise, raise error messages and ask user re-enter username and password.
##### 3. The client side code was merged into website.py
##### 4. The backend code was merged into api.py
##### 5. Edited on html files under `website/templates/`

### Known Issue(s):
##### Have not build it yet, might need do a throughtfully debugging.




