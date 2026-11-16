//go:build linux

package oidcprelink

import "syscall"

func changeTime(s *syscall.Stat_t) (int64, int64) { return s.Ctim.Sec, s.Ctim.Nsec }
