package ui

import (
	"context"
	"log"

	"goKeeperYandex/internal/client/models"
	"goKeeperYandex/package/logger"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// GRPCClienter интерфейс для клиента gRPC
type GRPCClienter interface {
	Register(ctx context.Context, user models.RegisterAndLogin) error
	Login(ctx context.Context, user models.RegisterAndLogin) error
	MasterPasswordStoreOrCheck(ctx context.Context, masterPassword string) (bool, error)
	AddDataToServer(ctx context.Context, data models.Data) error
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
			u.logger.Info("Банковские карты")
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
			u.logger.Info("Пароли")
			updateRightContent([]fyne.CanvasObject{
				widget.NewLabel("Пароли"),
				// Добавьте другие виджеты для отображения информации о паролях
			})
		}),
		widget.NewButton("Заметки", func() {
			u.logger.Info("Заметки")
			updateRightContent([]fyne.CanvasObject{
				widget.NewLabel("Заметки"),
				// Добавьте другие виджеты для отображения информации о заметках
			})
		}),
		widget.NewButton("Файлы", func() {
			u.logger.Info("Файлы")
			updateRightContent([]fyne.CanvasObject{
				widget.NewLabel("Файлы"),
				// Добавьте другие виджеты для отображения информации о файлах
			})
		}),
	})
	updateRightContent([]fyne.CanvasObject{
		widget.NewLabel("Содержимое:"),
	})
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

	// mock data
	bankCards := []models.BankCard{
		{
			Title:      "YellowBank",
			CardNumber: "1234 5678 1234 5678",
			ExpiryDate: "12/23",
			Cvv:        "123",
		},
		{
			Title:      "GreenBank",
			CardNumber: "9876 5432 9876 5432",
			ExpiryDate: "11/22",
			Cvv:        "321",
		},
	}

	// dataFromServer, err := u.handler.GetDataFromServer(u.ctx, models.DataTypeBankCard)
	// if err != nil {
	// 	u.logger.Error("Failed to get bank cards from server:", err)
	// 	return widget.NewLabel("Failed to get bank cards from server: " + err.Error())
	// }

	// bankCards, ok := dataFromServer.([]models.BankCard)
	// if !ok {
	// 	u.logger.Error("Failed to convert data to bank cards")
	// 	return widget.NewLabel("Failed to convert data to bank cards")
	// }

	// Создаем список виджетов для отображения банковских карт
	var bankCardsWidgets []fyne.CanvasObject
	for _, card := range bankCards {
		bankCardsWidgets = append(bankCardsWidgets, widget.NewLabel("Карта: "+card.CardNumber))
		bankCardsWidgets = append(bankCardsWidgets, widget.NewLabel("Срок действия: "+card.ExpiryDate))
		bankCardsWidgets = append(bankCardsWidgets, widget.NewLabel("CVV: "+card.Cvv))
		bankCardsWidgets = append(bankCardsWidgets, widget.NewSeparator())
	}

	return container.NewVBox(bankCardsWidgets...)
}
