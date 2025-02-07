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

// DataContent интерфейс для всех типов данных
type DataContent interface {
	isDataContent()
}

// Data структура для хранения данных
type Data struct {
	DataType DataTypes
	Data     DataContent
}

// DataToPass структура для передачи данных между клиентом и сервером
type DataToPass struct {
	DataType  DataTypes
	DataString string
}

// LoginPassword структура для хранения данных логина и пароля
type LoginPassword struct {
	Title    string
	Login    string
	Password string
}

func (LoginPassword) isDataContent() {}

// TextNote структура для хранения текстовой заметки
type TextNote struct {
	Title string
	Text  string
}

func (TextNote) isDataContent() {}

// BinaryData структура для хранения бинарных данных
type BinaryData struct {
	Title string
	Data  []byte
}

func (BinaryData) isDataContent() {}

// BankCard структура для хранения данных банковской карты
type BankCard struct {
	Title      string
	CardNumber string
	ExpiryDate string
	Cvv        string
}

func (BankCard) isDataContent() {}
