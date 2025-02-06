package ui

import (
	"context"
	"log"
	"os"
	"strconv"

	"goKeeperYandex/internal/client/models"
	"goKeeperYandex/package/logger"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// GRPCClienter интерфейс для клиента gRPC
type GRPCClienter interface {
	Register(ctx context.Context, user models.RegisterAndLogin) error
	Login(ctx context.Context, user models.RegisterAndLogin) error
	MasterPasswordStoreOrCheck(ctx context.Context, masterPassword string) (bool, error)
	AddDataToServer(ctx context.Context, data models.Data) error
	GetDataFromServer(ctx context.Context, dataType models.DataTypes) ([]models.Data, error)
}

// UI структура для графического интерфейса
type UI struct {
	ctx     context.Context
	handler GRPCClienter
	logger  *logger.Logger
}

// NewUI создает новый экземпляр UI
func NewUI(ctx context.Context, grpcClient GRPCClienter, log *logger.Logger) *UI {
	return &UI{
		ctx:     ctx,
		handler: grpcClient,
		logger:  log,
	}
}

// RunUI запускает графический интерфейс
func (u *UI) RunUI() {
	var err error
	// Создание приложения fyne
	a := app.New()
	w := a.NewWindow("GoKeeper Login/Registration")

	w.Resize(fyne.NewSize(640, 480))

	// Создание интерфейса для входа и регистрации
	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Username")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Password")

	label := widget.NewLabel("")

	loginButton := widget.NewButton("Login", func() {
		username := usernameEntry.Text
		password := passwordEntry.Text

		logmodel := models.RegisterAndLogin{Username: username, Password: password}

		err = u.handler.Login(u.ctx, logmodel)
		if err != nil {
			log.Println("Login failed:", err)
			label.SetText("Login failed: " + err.Error())
		} else {
			label.SetText("Login successful!")
			u.masterPasswordWindow(a)
			w.Close()
		}
	})

	registerButton := widget.NewButton("Register", func() {
		username := usernameEntry.Text
		password := passwordEntry.Text

		registerModel := models.RegisterAndLogin{Username: username, Password: password}

		err := u.handler.Register(u.ctx, registerModel)
		if err != nil {
			log.Println("Registration failed:", err)
			label.SetText("Registration failed: " + err.Error())
		} else {
			label.SetText("Registration successful!")
			u.masterPasswordWindow(a)
			w.Close()
		}
	})

	buttons := container.NewHBox(registerButton, loginButton)
	centeredButtons := container.NewCenter(buttons)

	w.SetContent(container.NewVBox(
		widget.NewLabel("Login/Register to GoKeeper"),
		usernameEntry,
		passwordEntry,
		centeredButtons,
		label,
	))

	// Запуск приложения
	w.ShowAndRun()
}

// masterPasswordWindow отображает окно для ввода мастер-пароля
func (u *UI) masterPasswordWindow(a fyne.App) {
	w := a.NewWindow("GoKeeper Master Password")

	w.Resize(fyne.NewSize(640, 480))

	// Создание интерфейса для ввода мастер-пароля
	masterPasswordEntry := widget.NewPasswordEntry()
	masterPasswordEntry.SetPlaceHolder("Master Password")

	label := widget.NewLabel("")

	confirmButton := widget.NewButton("Confirm", func() {
		masterPassword := masterPasswordEntry.Text

		ok, err := u.handler.MasterPasswordStoreOrCheck(u.ctx, masterPassword)
		if err != nil {
			log.Println("Master password check failed:", err)
			label.SetText("Master password check failed: " + err.Error())
		} else {
			if ok {
				label.SetText("Master password is correct!")
				u.showMainWindow(a)
				w.Close()
			} else {
				label.SetText("Master password is incorrect!")
			}
		}
	})

	w.SetContent(container.NewVBox(
		widget.NewLabel("Enter your master password"),
		masterPasswordEntry,
		confirmButton,
		label,
	))

	w.Show()
}

// showMainWindow отображает основное окно приложения
func (u *UI) showMainWindow(a fyne.App) {
	w := a.NewWindow("GoKeeper Client")

	w.Resize(fyne.NewSize(640, 480))

	// Создание интерфейса основного окна
	leftContent := container.NewVBox(
		widget.NewLabel("Сделайте выбор:"),
	)

	rightContent := container.NewVBox(
		widget.NewLabel("Содержимое:"),
	)

	// Инициализация содержимого
	u.resetContent(leftContent, rightContent)

	mainSplit := container.NewHSplit(leftContent, rightContent)
	mainSplit.Offset = 0.3 // Устанавливаем соотношение 30% к 70% для основной части

	w.SetContent(mainSplit)

	w.Show()
}

// resetContent обновляет содержимое левой и правой части основного окна
// Функция для восстановления исходного состояния
func (u *UI) resetContent(leftContent, rightContent *fyne.Container) {
	updateLeftContent := func(content []fyne.CanvasObject) {
		leftContent.Objects = content
		leftContent.Refresh()
	}

	updateRightContent := func(content []fyne.CanvasObject) {
		rightContent.Objects = content
		rightContent.Refresh()
	}

	updateLeftContent([]fyne.CanvasObject{
		widget.NewLabel("Сделайте выбор:"),
		widget.NewButton("Банковские карты", func() {
			updateRightContent([]fyne.CanvasObject{
				widget.NewLabel("Банковские карты"),
				u.showBankCards(),
			})
			updateLeftContent([]fyne.CanvasObject{
				widget.NewLabel("Добавить банковскую карту:"),
				widget.NewButton("Добавить", func() {
					u.logger.Info("Добавить банковскую карту")
					u.openAddBankCardWindow()
				}),
				widget.NewButton("Назад", func() {
					u.logger.Info("Назад")
					u.resetContent(leftContent, rightContent)
				}),
			})
		}),
		widget.NewButton("Пароли", func() {
			updateRightContent([]fyne.CanvasObject{
				widget.NewLabel("Пароли"),
				u.showPasswords(),
			})
			updateLeftContent([]fyne.CanvasObject{
				widget.NewLabel("Добавить логин и пароль:"),
				widget.NewButton("Добавить", func() {
					u.logger.Info("Добавить логин и пароль")
					u.openAddPasswordWindow()
				}),
				widget.NewButton("Назад", func() {
					u.logger.Info("Назад")
					u.resetContent(leftContent, rightContent)
				}),
			})
		}),
		widget.NewButton("Заметки", func() {
			updateRightContent([]fyne.CanvasObject{
				widget.NewLabel("Заметки"),
				u.showTextNotes(),
			})
			updateLeftContent([]fyne.CanvasObject{
				widget.NewLabel("Добавить заметку:"),
				widget.NewButton("Добавить", func() {
					u.logger.Info("Добавить заметку")
					u.openTextWindow("Заметка", "")
				}),
				widget.NewButton("Назад", func() {
					u.logger.Info("Назад")
					u.resetContent(leftContent, rightContent)
				}),
			})
		}),
		widget.NewButton("Файлы", func() {
			u.logger.Info("Файлы")
			updateRightContent([]fyne.CanvasObject{
				widget.NewLabel("Файлы"),
				u.showBinaryFiles(),
			})
			updateLeftContent([]fyne.CanvasObject{
				widget.NewLabel("Добавить файл:"),
				widget.NewButton("Добавить", func() {
					u.logger.Info("Добавить файл")
					u.openAddBinaryFileWindow()
				}),
				widget.NewButton("Назад", func() {
					u.logger.Info("Назад")
					u.resetContent(leftContent, rightContent)
				}),
			})
		}),
	})
	updateRightContent([]fyne.CanvasObject{
		widget.NewLabel("Содержимое:"),
	})
}

func (u *UI) openAddPasswordWindow() {
	newWindow := fyne.CurrentApp().NewWindow("Добавить пароль")
	newWindow.Resize(fyne.NewSize(400, 200))

	titleEntry := widget.NewEntry()
	titleEntry.SetPlaceHolder("Название пароля (пример: Google)")

	loginEntry := widget.NewEntry()
	loginEntry.SetPlaceHolder("Логин")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Пароль")

	saveButton := widget.NewButton("Сохранить", func() {
		u.logger.Info("Сохраняем пароль: " + titleEntry.Text)
		err := u.handler.AddDataToServer(u.ctx, models.Data{
			DataType: models.DataTypeLoginPassword,
			Data: models.LoginPassword{
				Title:    titleEntry.Text,
				Login:    loginEntry.Text,
				Password: passwordEntry.Text,
			},
		})
		if err != nil {
			log.Println("Failed to add password:", err)
			u.showMainWindow(fyne.CurrentApp())
		}
		newWindow.Close()
	})

	form := container.NewVBox(
		widget.NewLabel("Введите данные пароля:"),
		titleEntry,
		loginEntry,
		passwordEntry,
		saveButton,
	)

	newWindow.SetContent(form)
	newWindow.Show()
}

func (u *UI) showPasswords() fyne.CanvasObject {
	u.logger.Info("Получаем пароли")
	// Получаем данные о паролях с сервера
	dataFromServer, err := u.handler.GetDataFromServer(u.ctx, models.DataTypeLoginPassword)
	if err != nil {
		u.logger.Error("Failed to get passwords from server")
		return widget.NewLabel("Failed to get passwords from server: " + err.Error())
	}

	var passwords []models.LoginPassword
	for _, data := range dataFromServer {
		if password, ok := data.Data.(models.LoginPassword); ok {
			passwords = append(passwords, password)
		}
	}

	if len(passwords) == 0 {
		return widget.NewLabel("No passwords found")
	}

	// Создаем список виджетов для отображения паролей
	var passwordsWidgets []fyne.CanvasObject
	for _, password := range passwords {
		passwordsWidgets = append(passwordsWidgets, widget.NewLabel("Сервис: "+password.Title))
		passwordsWidgets = append(passwordsWidgets, widget.NewLabel("Логин: "+password.Login))
		passwordsWidgets = append(passwordsWidgets, widget.NewLabel("Пароль: "+password.Password))
		passwordsWidgets = append(passwordsWidgets, widget.NewSeparator())
	}

	return container.NewVBox(passwordsWidgets...)
}

func (u *UI) openTextWindow(title, text string) {
	newWindow := fyne.CurrentApp().NewWindow(title)
	newWindow.Resize(fyne.NewSize(400, 200))

	titleEntryTitle := widget.NewEntry()
	titleEntryTitle.SetText(title)

	textEntry := widget.NewMultiLineEntry()
	textEntry.SetText(text)

	saveButton := widget.NewButton("Сохранить", func() {
		u.logger.Info("Сохраняем текст: " + textEntry.Text)
		err := u.handler.AddDataToServer(u.ctx, models.Data{
			DataType: models.DataTypeTextNote,
			Data: models.TextNote{
				Title: titleEntryTitle.Text,
				Text:  textEntry.Text,
			},
		})
		if err != nil {
			log.Println("Failed to add text:", err)
			u.showMainWindow(fyne.CurrentApp())
		}
		newWindow.Close()
	})

	form := container.NewVBox(
		widget.NewLabel("Введите текст:"),
		titleEntryTitle,
		textEntry,
		saveButton,
	)

	newWindow.SetContent(form)
	newWindow.Show()
}

func (u *UI) showTextNotes() fyne.CanvasObject {
	u.logger.Info("Получаем заметки")
	// Получаем данные о заметках с сервера
	dataFromServer, err := u.handler.GetDataFromServer(u.ctx, models.DataTypeTextNote)
	if err != nil {
		u.logger.Error("Failed to get text notes from server")
		return widget.NewLabel("Failed to get text notes from server: " + err.Error())
	}

	var textNotes []models.TextNote
	for _, data := range dataFromServer {
		if textNote, ok := data.Data.(models.TextNote); ok {
			textNotes = append(textNotes, textNote)
		}
	}

	if len(textNotes) == 0 {
		return widget.NewLabel("No text notes found")
	}

	// Создаем список виджетов для отображения заметок
	var textNotesWidgets []fyne.CanvasObject
	for _, note := range textNotes {
		textNotesWidgets = append(textNotesWidgets, widget.NewLabel("Заметка: "+note.Title))
		textNotesWidgets = append(textNotesWidgets, widget.NewLabel("Текст: "+note.Text))
		textNotesWidgets = append(textNotesWidgets, widget.NewSeparator())
	}

	return container.NewVBox(textNotesWidgets...)
}

// openAddBankCardWindow открывает новое окно с полями для ввода данных банковской карты
func (u *UI) openAddBankCardWindow() {
	newWindow := fyne.CurrentApp().NewWindow("Добавить банковскую карту")
	newWindow.Resize(fyne.NewSize(400, 200))

	titleEntry := widget.NewEntry()
	titleEntry.SetPlaceHolder("Название карты (пример: YellowBank)")

	cardNumberEntry := widget.NewEntry()
	cardNumberEntry.SetPlaceHolder("Номер карты")

	expiryEntry := widget.NewEntry()
	expiryEntry.SetPlaceHolder("Срок действия (MM/YY)")

	cvvEntry := widget.NewEntry()
	cvvEntry.SetPlaceHolder("CVV")

	saveButton := widget.NewButton("Сохранить", func() {
		u.logger.Info("Сохраняем карту: " + titleEntry.Text)
		err := u.handler.AddDataToServer(u.ctx, models.Data{
			DataType: models.DataTypeBankCard,
			Data: models.BankCard{
				Title:      titleEntry.Text,
				CardNumber: cardNumberEntry.Text,
				ExpiryDate: expiryEntry.Text,
				Cvv:        cvvEntry.Text,
			},
		})
		if err != nil {
			log.Println("Failed to add bank card:", err)
			u.showMainWindow(fyne.CurrentApp())
		}
		newWindow.Close()
	})

	form := container.NewVBox(
		widget.NewLabel("Введите данные карты:"),
		titleEntry,
		cardNumberEntry,
		expiryEntry,
		cvvEntry,
		saveButton,
	)

	newWindow.SetContent(form)
	newWindow.Show()
}

// showBankCards отображает список банковских карт
func (u *UI) showBankCards() fyne.CanvasObject {
	u.logger.Info("Получаем банковские карты")
	// Получаем данные о банковских картах с сервера
	dataFromServer, err := u.handler.GetDataFromServer(u.ctx, models.DataTypeBankCard)
	if err != nil {
		u.logger.Error("Failed to get bank cards from server")
		return widget.NewLabel("Failed to get bank cards from server: " + err.Error())
	}

	var bankCards []models.BankCard
	for _, data := range dataFromServer {
		if bankCard, ok := data.Data.(models.BankCard); ok {
			bankCards = append(bankCards, bankCard)
		}
	}

	if len(bankCards) == 0 {
		return widget.NewLabel("No bank cards found")
	}

	// Создаем список виджетов для отображения банковских карт
	var bankCardsWidgets []fyne.CanvasObject
	for _, card := range bankCards {
		bankCardsWidgets = append(bankCardsWidgets, widget.NewLabel("Банк: "+card.Title))
		bankCardsWidgets = append(bankCardsWidgets, widget.NewLabel("Карта: "+card.CardNumber))
		bankCardsWidgets = append(bankCardsWidgets, widget.NewLabel("Срок действия: "+card.ExpiryDate))
		bankCardsWidgets = append(bankCardsWidgets, widget.NewLabel("CVV: "+card.Cvv))
		bankCardsWidgets = append(bankCardsWidgets, widget.NewSeparator())
	}

	return container.NewVBox(bankCardsWidgets...)
}

// openAddBinaryFileWindow открывает новое окно для выбора и сохранения бинарного файла
func (u *UI) openAddBinaryFileWindow() {
	newWindow := fyne.CurrentApp().NewWindow("Добавить бинарный файл")
	newWindow.Resize(fyne.NewSize(400, 200))

	titleEntry := widget.NewEntry()
	titleEntry.SetPlaceHolder("Название файла")

	filePathEntry := widget.NewEntry()
	filePathEntry.SetPlaceHolder("Путь к файлу")

	selectFileButton := widget.NewButton("Выбрать файл", func() {
		dialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				log.Println("Failed to open file:", err)
				return
			}
			if reader == nil {
				return
			}
			filePathEntry.SetText(reader.URI().Path())
		}, newWindow)
		dialog.Show()
	})

	saveButton := widget.NewButton("Сохранить", func() {
		u.logger.Info("Сохраняем файл: " + titleEntry.Text)
		filePath := filePathEntry.Text
		fileData, err := os.ReadFile(filePath)
		if err != nil {
			log.Println("Failed to read file:", err)
			return
		}

		err = u.handler.AddDataToServer(u.ctx, models.Data{
			DataType: models.DataTypeBinaryData,
			Data: models.BinaryData{
				Title: titleEntry.Text,
				Data:  fileData,
			},
		})
		if err != nil {
			log.Println("Failed to add binary file:", err)
			u.showMainWindow(fyne.CurrentApp())
		}
		newWindow.Close()
	})

	form := container.NewVBox(
		widget.NewLabel("Введите данные файла:"),
		titleEntry,
		filePathEntry,
		selectFileButton,
		saveButton,
	)

	newWindow.SetContent(form)
	newWindow.Show()
}

// showBinaryFiles отображает список бинарных файлов
func (u *UI) showBinaryFiles() fyne.CanvasObject {
	u.logger.Info("Получаем бинарные файлы")
	// Получаем данные о бинарных файлах с сервера
	dataFromServer, err := u.handler.GetDataFromServer(u.ctx, models.DataTypeBinaryData)
	if err != nil {
		u.logger.Error("Failed to get binary files from server")
		return widget.NewLabel("Failed to get binary files from server: " + err.Error())
	}

	var binaryFiles []models.BinaryData
	for _, data := range dataFromServer {
		if binaryFile, ok := data.Data.(models.BinaryData); ok {
			binaryFiles = append(binaryFiles, binaryFile)
		}
	}

	if len(binaryFiles) == 0 {
		return widget.NewLabel("No binary files found")
	}

	// Создаем список виджетов для отображения бинарных файлов
	var binaryFilesWidgets []fyne.CanvasObject
	for _, file := range binaryFiles {
		file := file // захват переменной
		binaryFilesWidgets = append(binaryFilesWidgets, widget.NewLabel("Файл: "+file.Title))
		binaryFilesWidgets = append(binaryFilesWidgets, widget.NewLabel("Размер: "+strconv.Itoa(len(file.Data))+" байт"))
		saveButton := widget.NewButton("Сохранить", func() {
			dialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
				if err != nil {
					log.Println("Failed to save file:", err)
					return
				}
				if writer == nil {
					return
				}
				defer writer.Close()

				_, err = writer.Write(file.Data)
				if err != nil {
					log.Println("Failed to write file:", err)
					return
				}
				u.logger.Info("Файл сохранен: " + writer.URI().Path())
			}, fyne.CurrentApp().Driver().AllWindows()[0])
			dialog.SetFileName(file.Title)
			dialog.Show()
		})
		binaryFilesWidgets = append(binaryFilesWidgets, saveButton)
		binaryFilesWidgets = append(binaryFilesWidgets, widget.NewSeparator())
	}

	return container.NewVBox(binaryFilesWidgets...)
}
