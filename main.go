package main

import (
	"database/sql"
	"flag"
	"fmt"

	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"sync"
	"text/template"

	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"

	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var userID string

var store = sessions.NewCookieStore([]byte("mysession"))

var db *sql.DB

var err error

func CreateAconut(res http.ResponseWriter, req *http.Request) {
	db, err2 := dbConn()
	if err2 != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	defer db.Close()

	if req.Method != "POST" {
		http.ServeFile(res, req, "static/templates/register.html")
		return
	}

	Username := req.FormValue("Name")
	Surname := req.FormValue("Surname")
	Iin := req.FormValue("Iin")
	Password := req.FormValue("Password")
	Phone := req.FormValue("Phone")
	City := req.FormValue("City")
	Nationality := req.FormValue("Nationality")
	Age := req.FormValue("Age")

	var user string
	err := db.QueryRow("SELECT name FROM diplom.sing_up WHERE name=?", Username).Scan(&user)
	switch {
	case err == sql.ErrNoRows:
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(res, "Server error 1", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO diplom.sing_up (name, surname, iin, password_, phone, city, nationality, age , Path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ? )",
			Username, Surname, Iin, string(hashedPassword), Phone, City, Nationality, Age, "null")
		if err != nil {
			log.Println("Error executing SQL query:", err)
			http.Error(res, "Server error 2: "+err.Error(), http.StatusInternalServerError)
			return
		}

	case err != nil:
		http.Error(res, "Server error 3", http.StatusInternalServerError)
		return
	}

	http.Redirect(res, req, "/login", http.StatusFound)
}

func loginPage(res http.ResponseWriter, req *http.Request) {
	db, err2 := dbConn()
	if err2 != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}

	if req.Method != "POST" {
		http.ServeFile(res, req, "static/templates/login.html")
		return
	}

	iin := req.FormValue("iin")
	password := req.FormValue("password")

	var databaseUsername string
	var databasePassword string

	// err := db.QueryRow("SELECT iin, password_ FROM  diplom.sing_up  WHERE iin=?", iin).Scan(&databaseUsername, &databasePassword)
	err := db.QueryRow("SELECT	id, iin, password_ FROM  diplom.sing_up  WHERE iin=?", iin).Scan(&userID, &databaseUsername, &databasePassword)
	if err != nil {
		http.Redirect(res, req, "/login", http.StatusFound)
		return
	}
	fmt.Println("id ", userID)
	err = bcrypt.CompareHashAndPassword([]byte(databasePassword), []byte(password))
	if err != nil {
		http.Redirect(res, req, "/login", http.StatusFound)
		return
	}

	http.Redirect(res, req, "/admin_index?userID="+userID, 301)

	defer db.Close()
}

type upfile struct {
	ID     int
	Title  string
	Text   string
	Region string
	Path   string
	Count  int
}

var tmpl = template.Must(template.ParseGlob("static/templates/*.html"))

func News(w http.ResponseWriter, r *http.Request) {

	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	defer db.Close()
	var selDB *sql.Rows
	if r.Method == "POST" {
		region := r.FormValue("region")
		city := r.FormValue("city")

		fmt.Println("region ---", region)

		if region == "region" {
			sel, err := db.Query("SELECT * FROM diplom.upload WHERE region =?", region)
			selDB = sel
			if err != nil {
				panic(err.Error())
			}
		} else if city == "city" {
			sel, err := db.Query("SELECT * FROM diplom.upload WHERE region =?", city)
			selDB = sel
			if err != nil {
				panic(err.Error())
			}
		}

	} else {
		sel, err := db.Query("SELECT * FROM diplom.upload")
		selDB = sel
		if err != nil {
			panic(err.Error())
		}
	}

	userID := r.URL.Query().Get("userID")
	r.Header.Set("User-ID", userID)

	upld := upfile{}
	res := []upfile{}

	for selDB.Next() {
		var id int
		var title, text, region, path string

		err = selDB.Scan(&id, &title, &text, &region, &path)
		if err != nil {
			panic(err.Error())
		}
		upld.ID = id
		upld.Title = title
		upld.Text = text
		upld.Region = region
		upld.Path = path
		upld.Count = upld.Count + 1

		fmt.Println("count ", upld.Count)

		res = append(res, upld)
	}
	upld.Count = len(res)

	if upld.Count > 0 {
		tmpl.ExecuteTemplate(w, "news.html", res)
	} else {
		tmpl.ExecuteTemplate(w, "news.html", nil)
	}

	db.Close()

}
func uploadFiles(w http.ResponseWriter, r *http.Request) {

	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	if r.Method != "POST" {

		http.ServeFile(w, r, "static/templates/send.html")
		return
	}
	title := r.FormValue("title")
	text := r.FormValue("text")
	region := r.FormValue("region")

	r.ParseMultipartForm(200000)
	if r == nil {
		fmt.Fprintf(w, "No files can be selected\n")
	}

	formdata := r.MultipartForm
	fil := formdata.File["files"]
	for i := range fil {
		file, err := fil[i].Open()
		if err != nil {
			fmt.Fprintln(w, err)
			return
		}
		defer file.Close()

		tempFile, err := ioutil.TempFile("static/assets/uploadimage/", "upload-*.jpg")

		if err != nil {
			fmt.Println(err)
		}
		defer tempFile.Close()

		filepath := tempFile.Name()
		fileBytes, err := ioutil.ReadAll(file)
		if err != nil {
			fmt.Println(err)
		}

		tempFile.Write(fileBytes)

		insForm, err := db.Prepare("INSERT INTO diplom.upload(title, text, region, path) VALUES(?,?,?,?)")
		if err != nil {
			panic(err.Error())
		} else {
			log.Println("data insert successfully . . .")
		}
		insForm.Exec(title, text, region, filepath)

		log.Printf("Successfully Uploaded File\n")
		defer db.Close()

		http.Redirect(w, r, "/home", 301)
	}

}
func imageHandler(w http.ResponseWriter, r *http.Request) {

	uploadImage(w, r, userID)

}
func uploadImage(w http.ResponseWriter, r *http.Request, userID string) {

	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	if r.Method != "POST" {

		http.ServeFile(w, r, "static/templates/photo.html")

		return
	}

	r.ParseMultipartForm(200000)
	if r == nil {
		fmt.Fprintf(w, "No files can be selected\n")
	}
	fmt.Print(userID)

	formdata := r.MultipartForm
	fil := formdata.File["files"]
	for i := range fil {
		file, err := fil[i].Open()
		if err != nil {
			fmt.Fprintln(w, err)
			return
		}
		defer file.Close()

		tempFile, err := ioutil.TempFile("static/assets/uploadimage/", "upload-*.jpg")

		if err != nil {
			fmt.Println(err)
		}
		defer tempFile.Close()

		filepath := tempFile.Name()
		fileBytes, err := ioutil.ReadAll(file)
		if err != nil {
			fmt.Println(err)
		}

		tempFile.Write(fileBytes)

		insForm, err := db.Prepare("Update diplom.sing_up set Path = ? where id =?")
		if err != nil {
			panic(err.Error())
		} else {
			log.Println("data insert successfully . . .")
		}
		insForm.Exec(filepath, userID)
		fmt.Print(userID)
		log.Printf("Successfully Uploaded File\n")
		defer db.Close()

		http.Redirect(w, r, "/profile", 301)
	}

}

type templateHandler struct {
	once     sync.Once
	filename string
	templ    *template.Template
}

func (t *templateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.once.Do(func() {
		t.templ = template.Must(template.ParseFiles(filepath.Join("static/templates", t.filename)))
	})
	t.templ.Execute(w, r)

}
func dbConn() (*sql.DB, error) {
	db, err := sql.Open("mysql", "root:root@/diplom")
	if err != nil {
		return nil, err
	}
	fmt.Println("SQL connected")
	return db, nil
}
func UserHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("userID")
	fmt.Fprintf(w, "Hello, User %s! This is the user page.", userID)
}
func CustomHeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := r.Header.Get("User-ID")
		w.Header().Set("X-User-ID", userID)
		next.ServeHTTP(w, r)

	})
}

type upAdmin struct {
	ID          int
	Name        string
	Surname     string
	Iin         string
	Phone       string
	City        string
	Nationality string
	Age         int
	Password    string
	Path        string
}

func AdminHandler(w http.ResponseWriter, r *http.Request) {

	Admin(w, r, userID)
	// Photo(w, r, userID)
}

var tmpl6 = template.Must(template.ParseGlob("static/templates/html/*.html"))

func Admin(w http.ResponseWriter, r *http.Request, userID string) {
	db, err2 := dbConn()
	if err2 != nil {
		http.Error(w, "Error connecting to database", http.StatusInternalServerError)
		log.Println("Error connecting to database:", err)
		return
	}
	defer db.Close()

	var res []upAdmin

	var selDB *sql.Rows

	sel, err := db.Query("SELECT * from sing_up where id = ?", userID)
	if err != nil {
		http.Error(w, "Error querying database", http.StatusInternalServerError)
		log.Println("Error querying database:", err)
		return
	}
	selDB = sel
	defer sel.Close()

	if selDB.Next() {
		var id, age int
		var name, surname, iin, phone, city, nationality, password, path string

		err = selDB.Scan(&id, &name, &surname, &iin, &password, &phone, &city, &nationality, &age, &path)
		if err != nil {
			http.Error(w, "Error scanning database row", http.StatusInternalServerError)
			log.Println("Error scanning database row:", err)
			return
		}

		upld := upAdmin{
			ID:          id,
			Name:        name,
			Surname:     surname,
			Iin:         iin,
			Phone:       phone,
			City:        city,
			Nationality: nationality,
			Age:         age,
			Password:    password,
			Path:        path,
		}
		res = append(res, upld)

		// res = append(res, upld) // Append user data to the slice
	} else {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err := tmpl6.ExecuteTemplate(w, "profile.html", res); err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		log.Println("Error executing template:", err)
	}

}

func updateHandler(w http.ResponseWriter, r *http.Request) {
	UpdateInfoAboutUser(w, r, userID)
}
func UpdateInfoAboutUser(w http.ResponseWriter, r *http.Request, userID string) {
	db, err := dbConn()
	// if req.Method != "POST" {
	// 	http.ServeFile(res, req, "static/templates/update.html")
	// 	return

	// }
	if r.Method != "POST" {
		db, err := dbConn()

		var selDB *sql.Rows

		sel, err := db.Query("Select * from diplom.sing_up where id = ?", userID)

		selDB = sel
		if err != nil {
			http.Error(w, "Error querying database", http.StatusInternalServerError)
			log.Println("Error querying database:", err)
			return
		}
		defer sel.Close()

		var res []upAdmin // Slice to hold multiple user data

		for selDB.Next() {
			var id, age int
			var name, surname, iin, phone, city, nationality, password, path string

			err = selDB.Scan(&id, &name, &surname, &iin, &password, &phone, &city, &nationality, &age, &path)
			if err != nil {
				http.Error(w, "Error scanning database row", http.StatusInternalServerError)
				log.Println("Error scanning database row:", err)
				return
			}

			upld := upAdmin{ // Create a new upAdmin instance for each user
				ID:          id,
				Name:        name,
				Surname:     surname,
				Iin:         iin,
				Phone:       phone,
				City:        city,
				Nationality: nationality,
				Age:         age,
				Password:    password,
				Path:        path,
			}
			res = append(res, upld)

		}

		if err := tmpl.ExecuteTemplate(w, "update.html", res); err != nil {
			http.Error(w, "Error executing template", http.StatusInternalServerError)
			log.Println("Error executing template:", err)
		}

		db.Close()

	}
	username := r.FormValue("Name")
	surname := r.FormValue("Surname")
	password := r.FormValue("Password")
	phone := r.FormValue("Phone")
	city := r.FormValue("City")
	nationality := r.FormValue("Nationality")
	age := r.FormValue("Age")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Server error 1", http.StatusInternalServerError)
		return
	}
	_, err = db.Exec("Update diplom.sing_up SET name = ?, surname= ? , password_ = ?, phone = ?, city= ?, nationality= ? , age = ?  WHERE id = ?",
		username, surname, string(hashedPassword), phone, city, nationality, age, userID)

	if err != nil {
		http.Error(w, "Server error, unable to create your account.", 500)
		return
	}

	http.Redirect(w, r, "/profile", 301)
	w.Write([]byte("User info updated!"))

	defer db.Close()

}

type upfile2 struct {
	ID     int
	Title  string
	Text   string
	Region string
	Path   string
	Count  int
}
type udp struct {
	ID     int
	Title  string
	Text   string
	Region string
	Path   string
	Count  int
}
type comm struct {
	ID      int
	Author  string
	Comment string
}
type TemplateData struct {
	UploadData  []upfile2
	UploadData2 []udp
	UploadData3 []comm
}

var tmpl0 = template.Must(template.ParseGlob("static/templates/watch_news/*.html"))

func WatchPost(w http.ResponseWriter, r *http.Request) {
	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	log.Println("Log ")
	b := r.URL.Query().Get("id")

	var selDB *sql.Rows
	sel, err := db.Query("SELECT * FROM diplom.upload Where id = ?", b)
	selDB = sel
	if err != nil {
		panic(err.Error())
	}
	defer sel.Close()

	// upld := upfile2{}
	// res := []upfile2{}
	uploadData := []upfile2{}
	var mainid int
	for selDB.Next() {
		var upld upfile2
		var id int
		var title, text, region, path string

		err = selDB.Scan(&id, &title, &text, &region, &path)
		if err != nil {
			panic(err.Error())
		}
		mainid = id
		upld.ID = id
		upld.Title = title
		upld.Text = text
		upld.Region = region
		upld.Path = path

		uploadData = append(uploadData, upld)
	}
	/* -------- */
	sel2, err2 := db.Query("SELECT * FROM diplom.upload")
	selDB = sel2
	if err2 != nil {
		panic(err.Error())
	}

	uploadData2 := []udp{}
	for selDB.Next() {
		var upld udp
		var id int
		var title, text, region, path string

		err = selDB.Scan(&id, &title, &text, &region, &path)
		if err != nil {
			panic(err.Error())
		}
		upld.ID = id
		upld.Title = title
		upld.Text = text
		upld.Region = region
		upld.Path = path
		upld.Count = upld.Count + 1
		uploadData2 = append(uploadData2, upld)

	}
	/* -------- */
	sel3, err3 := db.Query("SELECT * FROM diplom.comment where id = ?", mainid)
	selDB = sel3
	if err3 != nil {
		panic(err.Error())
	}

	uploadData3 := []comm{}
	for selDB.Next() {
		var upld comm
		var id int
		var author, comment string

		err = selDB.Scan(&id, &author, &comment)
		if err != nil {
			panic(err.Error())
		}
		upld.ID = id
		upld.Author = author
		upld.Comment = comment

		uploadData3 = append(uploadData3, upld)

	}
	templateData := TemplateData{
		UploadData:  uploadData,
		UploadData2: uploadData2,
		UploadData3: uploadData3,
	}

	fmt.Println("id ", b)
	tmpl0.ExecuteTemplate(w, "single_page.html", templateData)
	defer db.Close()

}

// google login
var googleOauthConfig = &oauth2.Config{
	RedirectURL:  "http://localhost:8000/auth/google/callback",
	ClientID:     os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
	ClientSecret: os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
	Endpoint:     google.Endpoint,
}

const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

type User struct {
	// ID       int64
	GoogleID string
	Email    string
	Name     string
	Picture  string
}
type UserData struct {
	ID      string
	Email   string
	Name    string
	Picture string
}

func OauthGoogleLogin(w http.ResponseWriter, r *http.Request) {

	oauthState := generateStateOauthCookie(w)
	u := googleOauthConfig.AuthCodeURL(oauthState)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func OauthGoogleCallback(w http.ResponseWriter, r *http.Request) {

	oauthState, _ := r.Cookie("oauthstate")

	if r.FormValue("state") != oauthState.Value {
		log.Println("invalid oauth google state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	userData, err := getUserDataFromGoogle(r.FormValue("code"))
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	defer db.Close()
	var user User
	// err = db.QueryRow("Select id, google_id , email, name, picture From users where google_id = ? or email = ? ", userData.ID, userData.Email).Scan(&user.ID, &user.GoogleID, &user.Email, &user.Name, &user.Picture)
	err = db.QueryRow("Select  id , phone,iin, name, Path From diplom.sing_up where id = ? or iin = ? ", userData.ID, userData.Email).Scan(&userID, &user.GoogleID, &user.Email, &user.Name, &user.Picture)

	if err != nil {
		if err == sql.ErrNoRows {
			// _, err = db.Exec("INSERT INTO users (google_id, email, name, picture) VALUES (?, ?, ?, ?)", userData.ID, userData.Email, userData.Name, userData.Picture)
			_, err = db.Exec("INSERT INTO diplom.sing_up (name , surname , iin, password_,  phone ,city, nationality,age , Path) VALUES( ?, ?, ?, ?, ?,?,?,?,?)", userData.ID, userData.Name, userData.Email, "null", "isempty", "isempty", "isempty", 0, userData.Picture)
			if err != nil {
				log.Println("Failed to insert user:", err)
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
				return
			}
		} else { // Database error
			log.Println("Failed to query user:", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
	}
	session, err := store.Get(r, "mysession")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set user data in the session
	// session.Values["user_id"] = user.ID
	session.Values["user_id"] = userID
	session.Values["user_email"] = user.Email
	// You can store additional user data as needed

	// Save the session
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect the user to the homepage
	http.Redirect(w, r, "/admin_index", http.StatusFound)
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(20 * time.Minute)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}
func getUserDataFromGoogle(code string) (*UserData, error) {
	// Use code to get token and get user info from Google.
	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}

	response, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()

	var userData UserData
	err = json.NewDecoder(response.Body).Decode(&userData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode user data: %s", err.Error())
	}

	return &userData, nil
}
func uAdmin(res http.ResponseWriter, req *http.Request) {
	db, err2 := dbConn()
	if err2 != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}

	if req.Method != "POST" {
		http.ServeFile(res, req, "static/templates/html/auth-login-basic.html")
		return
	}

	name := req.FormValue("admin")
	password := req.FormValue("password")

	var databaseUsername string
	var databasePassword string

	err := db.QueryRow("SELECT	name, password from diplom.admin WHERE name=?", name).Scan(&databaseUsername, &databasePassword)
	if err != nil {
		http.Redirect(res, req, "/mainadmin", http.StatusFound)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(databasePassword), []byte(password))
	if err != nil {
		http.Redirect(res, req, "/mainadmin", http.StatusFound)
		return
	}

	http.Redirect(res, req, "/homeAdmin", 301)

	defer db.Close()
}

type upfile3 struct {
	ID          int
	Name        string
	Surname     string
	Iin         string
	Password    string
	Phone       string
	City        string
	Nationality string
	Age         int
	Path        string
}

var tmpl2 = template.Must(template.ParseGlob("static/templates/html/*.html"))

func IndexAdmin(r http.ResponseWriter, w *http.Request) {

	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}

	var selDB *sql.Rows
	sel, err := db.Query("SELECT * FROM diplom.sing_up")
	selDB = sel
	if err != nil {
		panic(err.Error())
	}
	defer sel.Close()

	upld := upfile3{}
	res := []upfile3{}

	for selDB.Next() {
		var id, age int
		var name, surname, iin, password_, phone, city, nationality, path string

		err = selDB.Scan(&id, &name, &surname, &iin, &password_, &phone, &city, &nationality, &age, &path)
		if err != nil {
			panic(err.Error())
		}
		upld.ID = id
		upld.Name = name
		upld.Surname = surname
		upld.Iin = iin
		upld.Password = password_
		upld.Phone = phone
		upld.City = city
		upld.Nationality = nationality
		upld.Age = age
		upld.Path = path
		res = append(res, upld)
	}

	tmpl2.ExecuteTemplate(r, "index.html", res)

	db.Close()

}

func Delete(w http.ResponseWriter, r *http.Request) {
	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	emp := r.URL.Query().Get("id")
	log.Println("deleted successfully", emp)
	delForm, err := db.Prepare("DELETE FROM diplom.sing_up WHERE id =?;")
	if err != nil {
		panic(err.Error())
	}
	delForm.Exec(emp)
	log.Println("deleted successfully", emp)
	defer db.Close()
	http.Redirect(w, r, "/homeAdmin", 301)
}
func Deleteuser(w http.ResponseWriter, r *http.Request) {
	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	emp := r.URL.Query().Get("id")
	log.Println("deleted successfully", emp)
	delForm, err := db.Prepare("DELETE FROM diplom.sing_up WHERE id =?;")
	if err != nil {
		panic(err.Error())
	}
	delForm.Exec(emp)
	log.Println("deleted successfully", emp)
	defer db.Close()
	http.Redirect(w, r, "/home", 301)
}

func updateSlideBar(w http.ResponseWriter, r *http.Request) {

	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	if r.Method != "POST" {

		http.ServeFile(w, r, "static/slideshow.html")

		return
	}

	r.ParseMultipartForm(200000)
	if r == nil {
		fmt.Fprintf(w, "No files can be selected\n")
	}
	fmt.Print(userID)

	formdata := r.MultipartForm
	fil := formdata.File["files"]
	for i := range fil {
		file, err := fil[i].Open()
		if err != nil {
			fmt.Fprintln(w, err)
			return
		}
		defer file.Close()

		tempFile, err := ioutil.TempFile("static/assets/uploadimage/", "upload-*.jpg")

		if err != nil {
			fmt.Println(err)
		}
		defer tempFile.Close()

		filepath := tempFile.Name()
		fileBytes, err := ioutil.ReadAll(file)
		if err != nil {
			fmt.Println(err)
		}

		tempFile.Write(fileBytes)

		insForm, err := db.Prepare("Update diplom.admin_image set path = ? where id =?")
		if err != nil {
			panic(err.Error())
		} else {
			log.Println("data insert successfully . . .")
		}
		insForm.Exec(filepath, 2)
		fmt.Print(userID)
		log.Printf("Successfully Uploaded File\n")
		defer db.Close()

		http.Redirect(w, r, "/", 301)
	}

}

type adminpost struct {
	ID     int
	Title  string
	Text   string
	Region string
	Path   string
	Count  int
}

var tmpl5 = template.Must(template.ParseGlob("static/templates/html/*.html"))

func admin_post(w http.ResponseWriter, r *http.Request) {
	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}

	userID := r.URL.Query().Get("userID")
	r.Header.Set("User-ID", userID)

	var selDB *sql.Rows
	sel, err := db.Query("SELECT * FROM diplom.upload")
	selDB = sel
	if err != nil {
		panic(err.Error())
	}
	defer sel.Close()

	upld := upfile{}
	res := []upfile{}

	for selDB.Next() {
		var id int
		var title, text, region, path string

		err = selDB.Scan(&id, &title, &text, &region, &path)
		if err != nil {
			panic(err.Error())
		}
		upld.ID = id
		upld.Title = title
		upld.Text = text
		upld.Region = region
		upld.Path = path

		res = append(res, upld)
	}
	upld.Count = len(res)

	if upld.Count > 0 {
		tmpl5.ExecuteTemplate(w, "posts.html", res)
	} else {
		tmpl5.ExecuteTemplate(w, "posts.html", nil)
	}

	db.Close()

}
func Admin_delete_post(w http.ResponseWriter, r *http.Request) {
	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	emp := r.URL.Query().Get("id")
	log.Println("deleted successfully", emp)
	delForm, err := db.Prepare("DELETE FROM diplom.upload WHERE id =?;")
	if err != nil {
		panic(err.Error())
	}
	delForm.Exec(emp)
	log.Println("deleted successfully", emp)
	defer db.Close()
	http.Redirect(w, r, "/admin_post_managment", 301)
}
func SendMessage(w http.ResponseWriter, r *http.Request) {

	Send(w, r, userID)

	// Photo(w, r, userID)
}
func Send(w http.ResponseWriter, r *http.Request, userId string) {

	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	if r.Method != "POST" {

		http.ServeFile(w, r, "static/templates/newrequest.html")
		return
	}
	title := r.FormValue("title")
	region := r.FormValue("region")
	text := r.FormValue("description")

	r.ParseMultipartForm(200000)
	if r == nil {
		fmt.Fprintf(w, "No files can be selected\n")
	}

	formdata := r.MultipartForm
	fil := formdata.File["files"]
	for i := range fil {
		file, err := fil[i].Open()
		if err != nil {
			fmt.Fprintln(w, err)
			return
		}
		defer file.Close()

		tempFile, err := ioutil.TempFile("static/assets/uploadimage/", "upload-*.jpg")

		if err != nil {
			fmt.Println(err)
		}
		defer tempFile.Close()

		filepath := tempFile.Name()
		fileBytes, err := ioutil.ReadAll(file)
		if err != nil {
			fmt.Println(err)
		}

		tempFile.Write(fileBytes)

		insForm, err := db.Prepare("INSERT INTO diplom.send(id, title, region, path, description, Status) VALUES(?,?,?,?,?, ?)")
		if err != nil {
			panic(err.Error())
		} else {
			log.Println("data insert successfully . . .")
		}
		insForm.Exec(userId, title, region, filepath, text, "В процессе")
		fmt.Println("userid is :", userId)

		log.Printf("Successfully Uploaded File\n")
		defer db.Close()

		http.Redirect(w, r, "/seemessage", 301)
	}

}

type upfile5 struct {
	ID     string
	Title  string
	Region string
	Path   string
	Count  int
	Text   string
	Time   string
	Status string
}

func seeSend(w http.ResponseWriter, r *http.Request) {

	seemessage(w, r, userID)
	// Photo(w, r, userID)
}

func seemessage(w http.ResponseWriter, r *http.Request, userID string) {
	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}

	var selDB *sql.Rows
	sel, err := db.Query("SELECT * FROM diplom.send where id = ?", userID)
	selDB = sel
	if err != nil {
		panic(err.Error())
	}
	defer sel.Close()

	upld := upfile5{}
	res := []upfile5{}

	for selDB.Next() {

		var id, title, region, path, text string
		var time, status string

		err = selDB.Scan(&id, &title, &region, &path, &text, &time, &status)
		if err != nil {
			panic(err.Error())
		}
		upld.ID = id
		upld.Title = title
		upld.Region = region
		upld.Path = path
		upld.Text = text
		upld.Time = time
		upld.Status = status

		res = append(res, upld)
	}
	upld.Count = len(res)

	if upld.Count > 0 {
		tmpl.ExecuteTemplate(w, "myrequests.html", res)
	} else {
		tmpl.ExecuteTemplate(w, "myrequests.html", nil)
	}

	db.Close()
}

type upfile6 struct {
	ID     string
	Title  string
	Region string
	Path   string
	Count  int
	Text   string
	Time   string
	Status string
}

func admin_see_send_messages(w http.ResponseWriter, r *http.Request) {
	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	var selDB *sql.Rows

	sel, err := db.Query("SELECT * FROM diplom.send")
	selDB = sel
	if err != nil {
		panic(err.Error())
	}

	userID := r.URL.Query().Get("userID")
	r.Header.Set("User-ID", userID)

	upld := upfile6{}
	res := []upfile6{}

	for selDB.Next() {

		var id, title, region, path, text, time, status string

		err = selDB.Scan(&id, &title, &region, &path, &text, &time, &status)
		if err != nil {
			panic(err.Error())
		}
		upld.ID = id
		upld.Title = title
		upld.Region = region
		upld.Path = path
		upld.Text = text
		upld.Time = time
		upld.Status = status

		res = append(res, upld)
	}
	upld.Count = len(res)

	if upld.Count > 0 {
		tmpl5.ExecuteTemplate(w, "sendedpost.html", res)
	} else {
		tmpl5.ExecuteTemplate(w, "sendedpost.html", nil)
	}

	db.Close()

}
func Index_page(w http.ResponseWriter, r *http.Request) {

	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	defer db.Close()

	tmpl.ExecuteTemplate(w, "index.html", r)

	db.Close()

}
func Accept(w http.ResponseWriter, r *http.Request) {
	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	emp := r.URL.Query().Get("id")

	delForm, err := db.Prepare("Update diplom.send SET Status = 'Ваш заказ принят'  WHERE id =?;")
	if err != nil {
		panic(err.Error())
	}
	delForm.Exec(emp)
	log.Println("updtaed successfully", emp)
	defer db.Close()
	http.Redirect(w, r, "/admin_see_send_messages", 301)
}
func Refuse(w http.ResponseWriter, r *http.Request) {
	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	emp := r.URL.Query().Get("id")
	log.Println("Updates successfully", emp)
	delForm, err := db.Prepare("Update diplom.send SET status = 'Ваш заказ отклонен'  WHERE id =?;")
	if err != nil {
		panic(err.Error())
	}
	delForm.Exec(emp)
	log.Println("updtaed successfully", emp)
	defer db.Close()
	http.Redirect(w, r, "/admin_see_send_messages", 301)
}
func Ready(w http.ResponseWriter, r *http.Request) {
	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	emp := r.URL.Query().Get("id")
	log.Println("deleted successfully", emp)
	delForm, err := db.Prepare("Update diplom.send SET status = 'Ваш заказ готов'  WHERE id =?;")
	if err != nil {
		panic(err.Error())
	}
	delForm.Exec(emp)
	log.Println("updtaed successfully", emp)
	defer db.Close()
	http.Redirect(w, r, "/admin_see_send_messages", 301)
}
func AdminWatchPost(w http.ResponseWriter, r *http.Request) {
	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	log.Println("Log ")
	b := r.URL.Query().Get("id")

	var selDB *sql.Rows
	sel, err := db.Query("SELECT * FROM diplom.send Where id = ?", b)
	selDB = sel
	if err != nil {
		panic(err.Error())
	}
	defer sel.Close()

	upld := upfile6{}
	res := []upfile6{}

	for selDB.Next() {
		var id string
		var title, region, path, text, time, status string

		err = selDB.Scan(&id, &title, &region, &path, &text, &time, &status)
		if err != nil {
			panic(err.Error())
		}
		upld.ID = id
		upld.Title = title
		upld.Text = text
		upld.Region = region
		upld.Path = path
		upld.Time = time
		upld.Status = status

		res = append(res, upld)
	}

	fmt.Println("id ", b)
	tmpl.ExecuteTemplate(w, "WatchPost.html", res)
	defer db.Close()

}
func AdminIndex(w http.ResponseWriter, r *http.Request) {

	mainindex(w, r, userID)
	// Photo(w, r, userID)
}

func mainindex(w http.ResponseWriter, r *http.Request, userID string) {
	db, err2 := dbConn()
	if err2 != nil {
		http.Error(w, "Error connecting to database", http.StatusInternalServerError)
		log.Println("Error connecting to database:", err)
		return
	}
	defer db.Close()

	var res []upAdmin

	var selDB *sql.Rows

	sel, err := db.Query("SELECT * from sing_up where id = ?", userID)
	if err != nil {
		http.Error(w, "Error querying database", http.StatusInternalServerError)
		log.Println("Error querying database:", err)
		return
	}
	selDB = sel
	defer sel.Close()

	if selDB.Next() {
		var id, age int
		var name, surname, iin, phone, city, nationality, password, path string

		err = selDB.Scan(&id, &name, &surname, &iin, &password, &phone, &city, &nationality, &age, &path)
		if err != nil {
			http.Error(w, "Error scanning database row", http.StatusInternalServerError)
			log.Println("Error scanning database row:", err)
			return
		}

		upld := upAdmin{
			ID:          id,
			Name:        name,
			Surname:     surname,
			Iin:         iin,
			Phone:       phone,
			City:        city,
			Nationality: nationality,
			Age:         age,
			Password:    password,
			Path:        path,
		}
		res = append(res, upld)

		// res = append(res, upld) // Append user data to the slice
	} else {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err := tmpl.ExecuteTemplate(w, "authorizedUser.html", res); err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		log.Println("Error executing template:", err)
	}

}
func Comments(w http.ResponseWriter, r *http.Request) {

	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	if r.Method != "POST" {

		http.ServeFile(w, r, "static/templates/watch_news/single_page.html")
		return
	}
	id := r.FormValue("postId")
	author := r.FormValue("author")
	comment := r.FormValue("comment")

	insForm, err := db.Prepare("INSERT INTO diplom.comment(id, author, comment) VALUES(?,?,?)")
	if err != nil {
		panic(err.Error())
	} else {
		log.Println("data insert successfully . . .")
	}
	insForm.Exec(id, author, comment)

	log.Printf("Successfully Uploaded File\n")
	defer db.Close()

	http.Redirect(w, r, "/buy?id="+id, 301)

}
func main() {

	db, err := dbConn()
	if err != nil {
		log.Println("Failed to connect to the database:", err)
		return
	}
	defer db.Close()

	var addr = flag.String("addr", ":8000", "the addr of the application")

	flag.Parse()
	r := newRoom()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/index", http.StatusFound)
	})
	router := http.NewServeMux()
	router.HandleFunc("/admin", UserHandler)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	http.HandleFunc("/signup", CreateAconut)
	http.HandleFunc("/login", loginPage)
	http.HandleFunc("/uploadfiles", uploadFiles)
	http.HandleFunc("/uploadimage", AdminHandler)
	http.HandleFunc("/home", News)
	http.Handle("/chat", &templateHandler{filename: "chat.html"})
	http.Handle("/room", r)
	http.HandleFunc("/profile", AdminHandler)
	http.HandleFunc("/update", updateHandler)
	http.Handle("/admin", CustomHeaderMiddleware(http.StripPrefix("/admin", router)))
	http.HandleFunc("/buy", WatchPost)
	http.HandleFunc("/auth/google/login", OauthGoogleLogin)
	http.HandleFunc("/auth/google/callback", OauthGoogleCallback)
	http.HandleFunc("/mainadmin", uAdmin)
	http.HandleFunc("/homeAdmin", IndexAdmin)
	http.HandleFunc("/image", imageHandler)
	http.HandleFunc("/dele", Delete)
	http.HandleFunc("/delete", Admin_delete_post)
	http.HandleFunc("/dele2", Deleteuser)
	http.HandleFunc("/slide_show", updateSlideBar)
	http.HandleFunc("/admin_post_managment", admin_post)
	http.HandleFunc("/send", SendMessage)
	http.HandleFunc("/seemessage", seeSend)
	http.HandleFunc("/admin_see_send_messages", admin_see_send_messages)
	http.HandleFunc("/index", Index_page)
	http.HandleFunc("/accept", Accept)
	http.HandleFunc("/refuse", Refuse)
	http.HandleFunc("/ready", Ready)
	http.HandleFunc("/admin_watch_post", AdminWatchPost)
	http.HandleFunc("/admin_index", AdminIndex)
	http.HandleFunc("/comments", Comments)
	go r.run()
	log.Println("Starting web server on", *addr)
	log.Println("Server started on: http://localhost:8000")

	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatal("listenAndServe: ", err)

	}
}
