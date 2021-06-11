# UOCIS322 - Project 7 #
Adding authentication and user interface to brevet time calculator service. The complete versoion of brevets APP.


### Author: Chengji Zheng           ### E-mail: chengjiz@uoregon.edu


### Changes
#### 1. Added User Login / Creat Account functions on the client side.
###### `website.py`, `login.html`, `register.html`
#### 2. Added User Login / Create Account function on the backend too. 
###### (1) For `create account`, it takes the user name and password and check if the username is duplicate, if not, then hashed the password and put them into the database. 
###### (2) For `login`, it takes the username and encrypted password (for security reason) to the backend, see if they are matched or not. If matched, then returns a success message and redirect the user to the correct page. Otherwise, raise error messages and ask user try again.
###### (3) Added get token and verify token to those getter functions `listAll`, `listOpenOnly` and `listCloseOnly`.
#### 3. The client side code was merged into website.py
#### 4. The backend code was merged into api.py
#### 5. Edited on html files under `website/templates/`





