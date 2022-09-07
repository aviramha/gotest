package main

import (
    "fmt"
    // "io"
    // "log"
    "net/http"
    "syscall"
)

func main() {
    fmt.Println(">> starting go")

    fmt.Println("FFF");
    a,b,c := syscall.Syscall6(uintptr(1),uintptr(2),uintptr(3),uintptr(4),uintptr(5),uintptr(6),uintptr(7));
    fmt.Println("FFF");
    fmt.Println(a, b, c);
    http.Get("http://www.google.com/robots.txt")
    // if err != nil {
    //     log.Fatal(err)
    // }

    // body, err := io.ReadAll(res.Body)
    // res.Body.Close()

    // if res.StatusCode > 299 {
    //     log.Fatalf("Response failed with status code: %d and\nbody: %s\n", res.StatusCode, body)
    // }

    // if err != nil {
    //     log.Fatal(err)
    // }

    // fmt.Printf("%s", body)

}
