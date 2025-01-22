package ui

import (
    "log"

    "fyne.io/fyne/v2"
    "fyne.io/fyne/v2/app"
    "fyne.io/fyne/v2/container"
    "fyne.io/fyne/v2/widget"
)

// GRPCClienter интерфейс для клиента gRPC
type GRPCClienter interface {
    Login(username, password string) (string, error)
    Register(username, password string) (string, error)
}

// UI структура для графического интерфейса
type UI struct {
    GrpcClient GRPCClienter
    token      string
}

// NewUI создает новый экземпляр UI
func NewUI(grpcClient GRPCClienter) *UI {
    return &UI{
        GrpcClient: grpcClient,
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

        u.token, err = u.GrpcClient.Login(username, password)
        if err != nil {
            log.Println("Login failed:", err)
            label.SetText("Login failed: " + err.Error())
        } else {
            label.SetText("Login successful!")
            u.showMainWindow(a)
            w.Close()
        }
    })

    registerButton := widget.NewButton("Register", func() {
        username := usernameEntry.Text
        password := passwordEntry.Text

        token, err := u.GrpcClient.Register(username, password)
        if err != nil {
            log.Println("Registration failed:", err)
            label.SetText("Registration failed: " + err.Error())
        } else {
            label.SetText("Registration successful!")
            log.Println("Token:", token)
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

// showMainWindow отображает основное окно приложения
func (u *UI) showMainWindow(a fyne.App) {
    w := a.NewWindow("GoKeeper Client")

    w.Resize(fyne.NewSize(640, 480))

    // Создание интерфейса основного окна
    leftContent := container.NewVBox(
        widget.NewLabel("Left Pane (20%)"),
    )

    topRightContent := container.NewVBox(
        widget.NewLabel("Top Right Pane (80%)"),
    )

    bottomRightContent := container.NewVBox(
        widget.NewLabel("Bottom Right Pane (80%)"),
    )

    rightSplit := container.NewVSplit(topRightContent, bottomRightContent)
    rightSplit.Offset = 0.5 // Устанавливаем соотношение 50% к 50% для правой части

    mainSplit := container.NewHSplit(leftContent, rightSplit)
    mainSplit.Offset = 0.2 // Устанавливаем соотношение 20% к 80% для основной части

    w.SetContent(mainSplit)

    w.Show()
}