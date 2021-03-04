// +build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

func maxingFdsLimit() {

	const LimitFds uint64 = 20000

	AssertRLimit := syscall.Rlimit{
		Cur: LimitFds,
		Max: LimitFds,
	}

	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)

	if err != nil {
		fmt.Println("Error Getting Rlimit: ", err)
		os.Exit(1)
	}

	rLimit.Max = LimitFds
	rLimit.Cur = LimitFds

	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		fmt.Println("Error Setting RLimit: ", err)
		os.Exit(1)
	}

	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)

	if err != nil {
		fmt.Println("Error Getting RLimit: ", err)
		os.Exit(1)
	}

	if rLimit != AssertRLimit {
		fmt.Println("Error Matching RLimit: ", rLimit)
		os.Exit(1)
	}

}

//MessageBoxPlain ..
func MessageBoxPlain(title, caption string) int {
	return 0
}
