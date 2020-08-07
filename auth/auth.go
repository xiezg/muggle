/*************************************************************************
# File Name: manage/auth.go
# Author: xiezg
# Mail: xzghyd2008@hotmail.com
# Created Time: 2019-06-28 12:35:21
# Last modified: 2020-08-06 10:31:24
************************************************************************/
package auth

import "io"
import "fmt"
import "sync"
import "time"
import "net/url"
import "net/http"
import "io/ioutil"
import "crypto/md5"
import "encoding/hex"
import "encoding/json"
import "github.com/xiezg/glog"

var cookieMap sync.Map
var session_maxAge int = 7 * 24 * 3600

type account_info struct {
	Name string `json:"name"`
	Pwd  string `json:"password"`
	ctx  interface{}
}

var loginErr = fmt.Errorf("login fails")

func common_response(w http.ResponseWriter, data interface{}, err error) {

	rsp := struct {
		Ret  int
		Msg  string
		Data interface{}
	}{
		Ret:  0,
		Msg:  "success",
		Data: data}

	if err != nil {
		rsp.Ret = 1
		rsp.Msg = err.Error()

		if err == loginErr {
			rsp.Ret = 2
		}
	}

	b, err := json.Marshal(rsp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if rsp.Ret == 2 {
		w.WriteHeader(http.StatusUnauthorized)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	io.WriteString(w, string(b))
}

func Logout(param []byte) (interface{}, error) {
	return nil, nil
}

func Login(query func(string, string) (interface{}, error), redirect string) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {

		defer r.Body.Close()

		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			common_response(w, nil, err)
			return
		}

		glog.V(10).Info(string(b))

		var accInfo account_info

		if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" { //name=123&password=123

			m, err := url.ParseQuery(string(b))
			if err != nil {
				common_response(w, nil, err)
				return
			}

			name, ok := m["name"]
			if !ok {
				common_response(w, nil, fmt.Errorf("can't find name"))
				return
			}

			pwd, ok := m["password"]
			if !ok {
				common_response(w, nil, fmt.Errorf("can't find password"))
				return
			}

			accInfo.Name = name[0]
			accInfo.Pwd = pwd[0]

		} else if err := json.Unmarshal(b, &accInfo); err != nil {
			common_response(w, nil, err)
			return
		}

		user_ctx, err := query(accInfo.Name, accInfo.Pwd)
		if err != nil {
			common_response(w, nil, fmt.Errorf("login fails.errmsg:%v", err))
			return
		}

		sessId := md5.Sum([]byte(time.Now().String() + accInfo.Name))

		cookie := &http.Cookie{
			Name:   "jsessionid",
			Value:  hex.EncodeToString(sessId[:]),
			Path:   "/",
			MaxAge: session_maxAge,
			Secure: false,
		}

		accInfo.ctx = user_ctx

		cookieMap.Store(hex.EncodeToString(sessId[:]), &accInfo)

		http.SetCookie(w, cookie)

		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusSeeOther)
		} else {
			common_response(w, user_ctx, nil)
		}
	}
}

func Auth(proc func(interface{}, []byte) (interface{}, error)) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {

		defer r.Body.Close()

		cookie, err := r.Cookie("jsessionid")
		if err != nil {

			if err == http.ErrNoCookie {
				common_response(w, nil, loginErr)
			} else {
				http.Error(w, fmt.Sprintf("%v", err), http.StatusBadRequest)
			}
			return
		}

		value, ok := cookieMap.Load(cookie.Value)
		if !ok {
			common_response(w, nil, loginErr)
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("%v", err), http.StatusBadRequest)
			return
		}

		result, err := proc(value.(*account_info).ctx, body)
		common_response(w, result, err)
	}
}
