package util

type Util struct{}

// 辅助函数：检查字符串是否在切片中
func Contains(s string, list []string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
