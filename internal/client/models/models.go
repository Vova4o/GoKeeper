package models

// Record структура для хранения данных
type Record struct {
	ID           int
	Data         Data
	CreatedAt    string
	Synchronized bool
}

// RegisterAndLogin модель для хранения логина и пароля
type RegisterAndLogin struct {
	Username string
	Password string
}

// DataTypes тип данных
type DataTypes int

// DateTypeModels тип данных
const (
	DataTypeLoginPassword DataTypes = iota
	DataTypeTextNote
	DataTypeBinaryData
	DataTypeBankCard
)

// Data структура для хранения данных
type Data struct {
	DataType DataTypes
	Data     interface{}
}

// LoginPassword структура для хранения данных логина и пароля
type LoginPassword struct {
	Title    string
	Login    string
	Password string
}

// TextNote структура для хранения текстовой заметки
type TextNote struct {
	Title string
	Text  string
}

// BinaryData структура для хранения бинарных данных
type BinaryData struct {
	Title string
	Data  []byte
}

// BankCard структура для хранения данных банковской карты
type BankCard struct {
	Title      string
	CardNumber string
	ExpiryDate string
	Cvv        string
}
