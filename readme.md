## Rest Api Python with JWT

Make sure your installed python 3.7 and several python library like flask, sqlalchemy, pyJwt or you can run `pip install -r requitments.txt`

Router list :
* http://127.0.0.1:5000/
* [POST] http://127.0.0.1:5000/login
* [POST] http://127.0.0.1:5000/register
* [GET] http://127.0.0.1:5000/sessions
* [GET] http://127.0.0.1:5000/sessions/{id}
* [GET] http://127.0.0.1:5000/sessions/create
* [GET] http://127.0.0.1:5000/sessions/update
* [GET] http://127.0.0.1:5000/sessions/delete

attribute name for token on header : `x-access-token`

request body data for register :


{
	"email":"123@gmail.com",
	"password":"test123",
	"password_confirmation":"test123",
	"username": "test123"
}

request body data for login :

{
	"password":"test123",
	"username": "test123"
}