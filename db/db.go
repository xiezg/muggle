/*************************************************************************
# File Name: db.go
# Author: xiezg
# Mail: xzghyd2008@hotmail.com
# Created Time: 2020-03-08 11:47:45
# Last modified: 2022-11-13 15:49:38
************************************************************************/

package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func InitMysql(ip string, port int, userName string, password string, dbname string) (*sql.DB, error) {

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8", userName, password, ip, port, dbname)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel() // releases resources if slowOperation completes before timeout elapses

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}

	db.SetMaxOpenConns(1000)
	db.SetMaxIdleConns(1000)
	db.Exec("set global wait_timeout=10")
	db.Exec("SET NAMES utf8")

	return db, nil
}
