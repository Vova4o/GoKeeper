package models

import "errors"

// User модель пользователя
type User struct {
	UserID             int    `sql:"PRIMARY_KEY"`
	Username           string `gorm:"uniqueIndex;not null"`
	PasswordHash       string `gorm:"not null"`
	MasterPasswordHash string `gorm:"default:null"`
	RefreshTokens      []RefreshToken
	PrivateInfo        []PrivateInfo
}

// ContextKey is a custom type for context keys
type ContextKey struct {
	name string
}

// UserIDKey is a key for user id in context
var UserIDKey = ContextKey{"user_id"}

// UserRegesred struct to return user tokens after registration
type UserRegesred struct {
	UserID       int
	AccessToken  string
	RefreshToken string
}

// Settings struct
type Settings struct {
	Host     string
	Port     int
	LogLevel string
	Secret   string
	Issuer   string
	DSN      string
}

// RefreshToken модель для хранения refresh токенов
type RefreshToken struct {
	UserID    int    `gorm:"not null"`
	Token     string `gorm:"not null"`
	IsRevoked bool   `gorm:"not null, default:false"`
}

// PrivateInfo модель для хранения приватной информации
type PrivateInfo struct {
	UserID   string `gorm:"not null"`
	DataType int    `gorm:"not null"`
	Data     Data   `gorm:"not null"`
}

// DataType тип данных
type DataType int

// Data модель для хранения данных
const (
	DataTypeLoginPassword DataType = 0
	DataTypeTextNote      DataType = 1
	DataTypeBinaryData    DataType = 2
	DataTypeBankCard      DataType = 3
)

// Data модель для хранения данных
type Data struct {
	DataType      DataType
	LoginPassword *LoginPassword
	TextNote      *TextNote
	BinaryData    *BinaryData
	BankCard      *BankCard
}

// LoginPassword модель для хранения логина и пароля
type LoginPassword struct {
	Username string
	Password string
}

// TextNote модель для хранения текстовой заметки
type TextNote struct {
	Title   string
	Content string
}

// BinaryData модель для хранения бинарных данных
type BinaryData struct {
	Filename string
	Data     []byte
}

// BankCard модель для хранения банковской карты
type BankCard struct {
	CardNumber string
	ExpiryDate string
	CVV        string
}

// Data модель для хранения данных
// type Data struct {
//     DataType DataType
//     Data     interface{}
// }

// GetData возвращает данные в виде указателя на тип T
func GetData[T any](data *Data, dataType DataType) (*T, bool) {
	switch dataType {
	case DataTypeLoginPassword:
		if v, ok := any(data.LoginPassword).(*T); ok {
			return v, true
		}
	case DataTypeTextNote:
		if v, ok := any(data.TextNote).(*T); ok {
			return v, true
		}
	case DataTypeBinaryData:
		if v, ok := any(data.BinaryData).(*T); ok {
			return v, true
		}
	case DataTypeBankCard:
		if v, ok := any(data.BankCard).(*T); ok {
			return v, true
		}
	}
	return nil, false
}

// NewData создает новый экземпляр Data
func NewData(dataType DataType, value any) (Data, error) {
	switch dataType {
	case DataTypeLoginPassword:
		return Data{DataType: dataType, LoginPassword: value.(*LoginPassword)}, nil
	case DataTypeTextNote:
		return Data{DataType: dataType, TextNote: value.(*TextNote)}, nil
	case DataTypeBinaryData:
		return Data{DataType: dataType, BinaryData: value.(*BinaryData)}, nil
	case DataTypeBankCard:
		return Data{DataType: dataType, BankCard: value.(*BankCard)}, nil
	default:
		return Data{}, errors.New("unsupported data type")
	}
}

// // GetLoginPassword возвращает данные типа LoginPassword
// func (d *Data) GetLoginPassword() (*LoginPassword, bool) {
//     if d.DataType == DataTypeLOGIN {
//         if lp, ok := d.Data.(LoginPassword); ok {
//             return &lp, true
//         }
//     }
//     return nil, false
// }

// // GetTextNote возвращает данные типа TextNote
// func (d *Data) GetTextNote() (*TextNote, bool) {
//     if d.DataType == DataTypeNOTE {
//         if tn, ok := d.Data.(TextNote); ok {
//             return &tn, true
//         }
//     }
//     return nil, false
// }

// // GetBinaryData возвращает данные типа BinaryData
// func (d *Data) GetBinaryData() (*BinaryData, bool) {
//     if d.DataType == DataTypeBINARY {
//         if bd, ok := d.Data.(BinaryData); ok {
//             return &bd, true
//         }
//     }
//     return nil, false
// }

// // GetBankCard возвращает данные типа BankCard
// func (d *Data) GetBankCard() (*BankCard, bool) {
//     if d.DataType == DataTypeCARD {
//         if bc, ok := d.Data.(BankCard); ok {
//             return &bc, true
//         }
//     }
//     return nil, false
// }
