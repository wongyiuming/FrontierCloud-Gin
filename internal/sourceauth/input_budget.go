package sourceauth

import "reflect"

// boundCapabilityInput estimates a conservative upper bound before JSON can
// allocate. Six bytes per input byte covers escaping; structural overhead and
// recursion are bounded as well. Chunked proof support must replace this
// temporary limit before large imports can be enabled.
func boundCapabilityInput(value reflect.Value, remaining *int, depth int) bool {
	if depth > 32 || *remaining < 0 {
		return false
	}
	if !value.IsValid() {
		*remaining -= 8
		return *remaining >= 0
	}
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			*remaining -= 8
			return *remaining >= 0
		}
		return boundCapabilityInput(value.Elem(), remaining, depth+1)
	case reflect.String:
		if value.Len() > *remaining/6 {
			return false
		}
		*remaining -= value.Len()*6 + 2
	case reflect.Slice, reflect.Array:
		if value.Len() > *remaining/2 {
			return false
		}
		*remaining -= value.Len()*2 + 2
		if value.Type().Elem().Kind() == reflect.Uint8 {
			if value.Len() > *remaining/2 {
				return false
			}
			*remaining -= value.Len() * 2
		} else {
			for i := 0; i < value.Len(); i++ {
				if !boundCapabilityInput(value.Index(i), remaining, depth+1) {
					return false
				}
			}
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			field := value.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			*remaining -= len(field.Name)*6 + 8
			if !boundCapabilityInput(value.Field(i), remaining, depth+1) {
				return false
			}
		}
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		*remaining -= 32
	default:
		return false
	}
	return *remaining >= 0
}
