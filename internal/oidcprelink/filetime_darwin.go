//go:build darwin

package oidcprelink

import "syscall"

func changeTime(s *syscall.Stat_t) (int64, int64) { return s.Ctimespec.Sec, s.Ctimespec.Nsec }
