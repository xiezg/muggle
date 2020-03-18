/*************************************************************************
# File Name: db.go
# Author: xiezg
# Mail: xzghyd2008@hotmail.com
# Created Time: 2020-03-08 11:47:45
# Last modified: 2020-03-10 17:34:28
************************************************************************/

package db

import "fmt"
import "database/sql"
import _ "github.com/go-sql-driver/mysql"

func InitMysql(ip string, port int, userName string, password string) (*sql.DB, error) {

	//dataSourceName := "jingzheng:JJ10RU6Xi3mFuRZN@tcp()/jingzheng?charset=utf8"
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/", userName, password, ip, port)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}

	db.SetMaxOpenConns(1000)
	db.SetMaxIdleConns(1000)
	db.Exec("set global wait_timeout=10")
	db.Exec("SET NAMES utf8")

	return db, nil
}
