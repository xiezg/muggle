/*************************************************************************
# File Name: manage/auth.go
# Author: xiezg
# Mail: xzghyd2008@hotmail.com
# Created Time: 2019-06-28 12:35:21
# Last modified: 2022-05-02 18:15:12
************************************************************************/
package auth

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/xiezg/glog"
)

var cookieMap sync.Map
var session_maxAge int = 3600

type account_info struct {
	Name string `json:"name"`
	Pwd  string `json:"password"`
	ctx  interface{}
}

type UserCtx struct {
	IP        string
	login_ctx interface{}
}

var loginErr = fmt.Errorf("login fails")

func common_response(w http.ResponseWriter, r *http.Request, data interface{}, err error) {

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

	w.Header().Set("Content-Type", "application/json; charset=utf-7")

	//支持跨域访问
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:63342")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	io.WriteString(w, string(b))
}

func Logout(param []byte) (interface{}, error) {
	return nil, nil
}

func Login(query func(string, string) (interface{}, error), redirect string) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {

		//defer r.Body.Close()

		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			common_response(w, r, nil, err)
			return
		}

		glog.V(10).Info(r.Header.Get("X-Real-IP"))
		glog.V(10).Info(string(b))

		var accInfo account_info

		if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" { //name=123&password=123

			m, err := url.ParseQuery(string(b))
			if err != nil {
				common_response(w, r, nil, err)
				return
			}

			name, ok := m["name"]
			if !ok {
				common_response(w, r, nil, fmt.Errorf("can't find name"))
				return
			}

			pwd, ok := m["password"]
			if !ok {
				common_response(w, r, nil, fmt.Errorf("can't find password"))
				return
			}

			accInfo.Name = name[0]
			accInfo.Pwd = pwd[0]

		} else if err := json.Unmarshal(b, &accInfo); err != nil {
			common_response(w, r, nil, err)
			return
		}

		user_ctx, err := query(accInfo.Name, accInfo.Pwd)
		if err != nil {
			glog.Errorf("user:%v login fails.err:%v", accInfo, err)
			common_response(w, r, nil, fmt.Errorf("login fails.errmsg:%v", err))
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

		accInfo.ctx = &UserCtx{r.Header.Get("X-Real-IP"), user_ctx}

		cookieMap.Store(hex.EncodeToString(sessId[:]), &accInfo)

		http.SetCookie(w, cookie)

		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusSeeOther)
		} else {
			common_response(w, r, user_ctx, nil)
		}
	}
}

//2022-05-02 17:47 proc函数中想要拿到IP地址，但是按照现在的结构，是做不到的

func Auth(proc func(interface{}, []byte) (interface{}, error)) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {

		//defer r.Body.Close()

		cookie, err := r.Cookie("jsessionid")
		if err != nil {

			if err == http.ErrNoCookie {
				common_response(w, r, nil, loginErr)
			} else {
				http.Error(w, fmt.Sprintf("%v", err), http.StatusBadRequest)
			}
			return
		}

		value, ok := cookieMap.Load(cookie.Value)
		if !ok {
			common_response(w, r, nil, loginErr)
			return
		}

		if r.Method == "GET" {
			result, err := proc(value.(*account_info).ctx, nil)
			common_response(w, r, result, err)
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("%v", err), http.StatusBadRequest)
			return
		}

		result, err := proc(value.(*account_info).ctx, body)
		common_response(w, r, result, err)
	}
}

func AuthUploadFile(proc func(interface{}, *http.Request) (interface{}, error)) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {

		cookie, err := r.Cookie("jsessionid")
		if err != nil {

			if err == http.ErrNoCookie {
				common_response(w, r, nil, loginErr)
			} else {
				http.Error(w, fmt.Sprintf("%v", err), http.StatusBadRequest)
			}
			return
		}

		value, ok := cookieMap.Load(cookie.Value)
		if !ok {
			common_response(w, r, nil, loginErr)
			return
		}

		result, err := proc(value.(*account_info).ctx, r)
		common_response(w, r, result, err)
	}
}

func AuthDownloadFile(proc func(interface{}, http.ResponseWriter, *http.Request)) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {

		cookie, err := r.Cookie("jsessionid")
		if err != nil {

			if err == http.ErrNoCookie {
				common_response(w, r, nil, loginErr)
			} else {
				http.Error(w, fmt.Sprintf("%v", err), http.StatusBadRequest)
			}
			return
		}

		value, ok := cookieMap.Load(cookie.Value)
		if !ok {
			common_response(w, r, nil, loginErr)
			return
		}

		proc(value.(*account_info).ctx, w, r)
	}
}
