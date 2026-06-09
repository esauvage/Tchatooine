#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QMessageBox>
#include <QMenu>

#include "imagesettings.h"
#include "metadatadialog.h"
#include "videosettings.h"

#include <QAudioDevice>
#include <QAudioInput>
#include <QCameraDevice>
#include <QMediaDevices>
#include <QMediaFormat>
#include <QMediaMetaData>
#include <QMediaRecorder>
#include <QVideoWidget>
#include <QVideoSink>

#include <QLineEdit>

#include <QAction>
#include <QActionGroup>
#include <QImage>
#include <QKeyEvent>
#include <QPalette>

#include <QDir>
#include <QTimer>

#if QT_CONFIG(permissions)
#include <QPermission>
#endif

#include <QBuffer>
#include <QDebug>


using namespace std;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::mainWindow) {
	ui->setupUi(this);

	//Multimedia
	// disable all buttons by default
	updateCameraActive(false);
	readyForCapture(false);
	ui->recordButton->setEnabled(false);
	ui->pauseButton->setEnabled(false);
	ui->stopButton->setEnabled(false);
	ui->metaDataButton->setEnabled(false);
    _videoSink = make_unique<QVideoSink>(this);
	// try to actually initialize camera & mic
	init();
    QVideoFrame vf;
    _videoSink->videoFrameChanged(vf);
//!end multimedia
	ui->lblMessages->clear();
	ui->edtMessage->clear();
	ui->statusbar->showMessage("Not connected");
	QString pseudo = qgetenv("USER");
	if (pseudo.isEmpty())
		pseudo = qgetenv("USERNAME");

	ui->edtPseudo->setText(pseudo);

	ui->cbxPair->addItem("87.88.38.108:9158");
	ui->cbxPair->addItem("localhost:9158");
	ui->cbxPair->addItem("176.187.157.48:9158");

	// Check if the system tray is available
	if (!QSystemTrayIcon::isSystemTrayAvailable()) {
		QMessageBox::warning(nullptr, "Avertissement", "Cet OS n'offre pas de service de système tray.");
	} else {
		// Set a tooltip and an icon for the tray icon
		_trayIcon.setToolTip("Tchatooine");
		_trayIcon.setIcon(QIcon(":/icones/Tatooine.png")); // Make sure to use a valid icon path

		// Set up a menu for the tray icon
		QMenu *trayMenu = new QMenu();
		trayMenu->addAction("Show Window");
		trayMenu->addSeparator();
		trayMenu->addAction("Exit");
		_trayIcon.setContextMenu(trayMenu);

		_trayIcon.show();
	}
	_videoEncodeur.init();
	connect(&_tchat, &Tchat::clientConnected, this, &MainWindow::onClientConnected);
	connect(&_tchat, &Tchat::serveurConnected, this, &MainWindow::onServeurConnected);
	connect(&_tchat, &Tchat::nouvMessage, this, &MainWindow::afficheMessage);
    connect(&_tchat, &Tchat::annuaireChanged, this, &MainWindow::affichePeers);
    connect(&_tchat, &Tchat::serveurIndisponible, this, &MainWindow::changeServeur);
    connect(&_tchat, &Tchat::peerImage, this, &MainWindow::showPeerImage);
    connect(ui->takeImageButton, &QPushButton::clicked, this, &MainWindow::takeImage);
	connect(ui->stopButton, &QPushButton::clicked, this, &MainWindow::stopCamera);
	connect(ui->recordButton, &QPushButton::clicked, this, &MainWindow::record);
	connect(ui->pauseButton, &QPushButton::clicked, this, &MainWindow::pause);
	connect(ui->actionExit, &QAction::triggered, this, &MainWindow::close);
	connect(ui->actionSettings, &QAction::triggered, this, &MainWindow::configureCaptureSettings);
	connect(ui->actionStartCamera, &QAction::triggered, this, &MainWindow::startCamera);
	connect(ui->actionStopCamera, &QAction::triggered, this, &MainWindow::stopCamera);
	connect(ui->muteButton, &QPushButton::toggled, this, &MainWindow::setMuted);
}

MainWindow::~MainWindow() {
    _tchat.close();
    delete ui;
}

void MainWindow::onClientConnected() {
	ui->statusbar->showMessage("Connected to " + _tchat.peerAddress().toString());
}

void MainWindow::onServeurConnected()
{
	ui->lblNbClients->setText(QString::number(_tchat.nbClients()));
}

void MainWindow::affichePeers()
{
	ui->lblPeers->setText(_tchat.peers().join('\n'));
}

void MainWindow::afficheMessage(QString message, bool isAncienMessage)
{
	ui->lblMessages->setText(ui->lblMessages->text() + message + "\n");
    if (!isActiveWindow() && !isAncienMessage) {
		// Show a notification balloon
		_trayIcon.showMessage(
			"Nouveau message",
			message,
			QSystemTrayIcon::Information,
			5000 // Display time in milliseconds
			);
		QApplication::alert(this);
	}
}

void MainWindow::on_edtMessage_editingFinished()
{
	_tchat.envoie(ui->edtMessage->text());
	ui->edtMessage->clear();
}

void MainWindow::on_cbxPair_currentIndexChanged(int index)
{
    ui->statusbar->showMessage("Connecting to " + ui->cbxPair->currentText());
	auto pair = ui->cbxPair->currentText().split(':');
	_tchat.init(pair.at(0), pair.at(1).toInt());
}

void MainWindow::on_edtPseudo_editingFinished()
{
	_tchat.setPseudo(ui->edtPseudo->text());
}

void MainWindow::init()
{
#if QT_CONFIG(permissions)
	// camera
	QCameraPermission cameraPermission;
	switch (qApp->checkPermission(cameraPermission)) {
	case Qt::PermissionStatus::Undetermined:
		qApp->requestPermission(cameraPermission, this, &MainWindow::init);
		return;
	case Qt::PermissionStatus::Denied:
		qWarning("Camera permission is not granted!");
		return;
	case Qt::PermissionStatus::Granted:
		break;
	}
	// microphone
	QMicrophonePermission microphonePermission;
	switch (qApp->checkPermission(microphonePermission)) {
	case Qt::PermissionStatus::Undetermined:
		qApp->requestPermission(microphonePermission, this, &MainWindow::init);
		return;
	case Qt::PermissionStatus::Denied:
		qWarning("Microphone permission is not granted!");
		return;
	case Qt::PermissionStatus::Granted:
		break;
	}
#endif

	m_audioInput.reset(new QAudioInput);
	m_captureSession.setAudioInput(m_audioInput.get());
    m_captureSession.setVideoSink(_videoSink.get());

	// Camera devices:
	videoDevicesGroup = new QActionGroup(this);
	videoDevicesGroup->setExclusive(true);
	updateCameras();
	connect(&m_devices, &QMediaDevices::videoInputsChanged, this, &MainWindow::updateCameras);

	connect(videoDevicesGroup, &QActionGroup::triggered, this, &MainWindow::updateCameraDevice);
	connect(ui->captureWidget, &QTabWidget::currentChanged, this, &MainWindow::updateCaptureMode);

	connect(ui->metaDataButton, &QPushButton::clicked, this, &MainWindow::showMetaDataDialog);

    connect(_videoSink.get(), &QVideoSink::videoFrameChanged, this, &MainWindow::onFrame);

	setCamera(QMediaDevices::defaultVideoInput());
}

void MainWindow::changeServeur()
{
    auto i = ui->cbxPair->currentIndex();
    ++i;
    i %= ui->cbxPair->count();
    ui->cbxPair->setCurrentIndex(i);
}

void MainWindow::setCamera(const QCameraDevice &cameraDevice)
{
	m_camera.reset(new QCamera(cameraDevice));
	m_captureSession.setCamera(m_camera.get());

	connect(m_camera.get(), &QCamera::activeChanged, this, &MainWindow::updateCameraActive);
	connect(m_camera.get(), &QCamera::errorOccurred, this, &MainWindow::displayCameraError);

	if (!m_mediaRecorder) {
		m_mediaRecorder.reset(new QMediaRecorder);
        m_captureSession.setVideoSink(_videoSink.get());
        // m_captureSession.setRecorder(m_mediaRecorder.get());
        // connect(m_mediaRecorder.get(), &QMediaRecorder::recorderStateChanged, this,
        // 		&MainWindow::updateRecorderState);
        // connect(m_mediaRecorder.get(), &QMediaRecorder::durationChanged, this,
        // 		&MainWindow::updateRecordTime);
        // connect(m_mediaRecorder.get(), &QMediaRecorder::errorChanged, this,
        // 		&MainWindow::displayRecorderError);
	}

	if (!m_imageCapture) {
		m_imageCapture.reset(new QImageCapture);
		m_captureSession.setImageCapture(m_imageCapture.get());
		connect(m_imageCapture.get(), &QImageCapture::readyForCaptureChanged, this,
				&MainWindow::readyForCapture);
        // connect(m_imageCapture.get(), &QImageCapture::imageCaptured, this,
        // 		&MainWindow::processCapturedImage);
		connect(m_imageCapture.get(), &QImageCapture::imageSaved, this, &MainWindow::imageSaved);
		connect(m_imageCapture.get(), &QImageCapture::errorOccurred, this,
				&MainWindow::displayCaptureError);
	}

    // m_captureSession.setVideoOutput(ui->viewfinder);

	updateCameraActive(m_camera->isActive());
	updateRecorderState(m_mediaRecorder->recorderState());
	readyForCapture(m_imageCapture->isReadyForCapture());

	updateCaptureMode();

	m_camera->start();
}

void MainWindow::keyPressEvent(QKeyEvent *event)
{
	if (event->isAutoRepeat())
		return;

	switch (event->key()) {
	case Qt::Key_CameraFocus:
		displayViewfinder();
		event->accept();
		break;
	case Qt::Key_Camera:
		if (m_doImageCapture) {
			takeImage();
		} else {
			if (m_mediaRecorder->recorderState() == QMediaRecorder::RecordingState)
				stop();
			else
				record();
		}
		event->accept();
		break;
	default:
		QMainWindow::keyPressEvent(event);
	}
}

void MainWindow::updateRecordTime()
{
	QString str = tr("Recorded %1 sec").arg(m_mediaRecorder->duration() / 1000);
	ui->statusbar->showMessage(str);
}

void MainWindow::showPeerImage(const QUuid &pair, const QImage &img){
    if (!_labels.contains(pair)) {
        _labels[pair] = new QLabel(ui->videoConf);
        auto *layout = dynamic_cast<QGridLayout *>(ui->videoConf->layout());
        if (!layout) {
            return;
        }
        auto index = _labels.size();
        auto nbCols = layout->columnCount();
        auto nbRows = layout->rowCount();
        if ((index >= nbCols * nbRows) && (nbRows > nbCols)){
            nbCols++;
            while (layout->count()) {
                layout->takeAt(0);
            }
         }
        for (int i = 0; i < _labels.keys().size(); ++i) {
            int row = i / nbCols;
            int col = i % nbCols;

            layout->addWidget(_labels[_labels.keys()[i]], row, col);
        }
    }
    auto label = _labels[pair];
    QImage scaledImage =
        img.scaled(label->size(), Qt::KeepAspectRatio, Qt::SmoothTransformation);

    label->setPixmap(QPixmap::fromImage(scaledImage));
    // label->setSizePolicy(QSizePolicy()); //Can't resize anymore
    ui->stackedWidget->setCurrentIndex(2);
}

void MainWindow::processCapturedImage(int requestId, const QImage &img)
{
    Q_UNUSED(requestId);
    QImage scaledImage =
        img.scaled(ui->viewfinder->size(), Qt::KeepAspectRatio, Qt::SmoothTransformation);

    ui->lastImagePreviewLabel->setPixmap(QPixmap::fromImage(scaledImage));
    ui->lastImagePreviewLabel->setSizePolicy(QSizePolicy()); //Can't resize anymore

    // Display captured image for 4 seconds.
    // displayCapturedImage();
    // QTimer::singleShot(4000, this, &MainWindow::displayViewfinder);
}

void MainWindow::configureCaptureSettings()
{
	if (m_doImageCapture)
		configureImageSettings();
	else
		configureVideoSettings();
}

void MainWindow::configureVideoSettings()
{
	VideoSettings settingsDialog(m_mediaRecorder.get());

	if (settingsDialog.exec())
		settingsDialog.applySettings();
}

void MainWindow::configureImageSettings()
{
	ImageSettings settingsDialog(m_imageCapture.get());

	if (settingsDialog.exec() == QDialog::Accepted)
		settingsDialog.applyImageSettings();
}

void MainWindow::record()
{
	m_mediaRecorder->record();
	updateRecordTime();
}

void MainWindow::pause()
{
	m_mediaRecorder->pause();
}

void MainWindow::stop()
{
	m_mediaRecorder->stop();
}

void MainWindow::setMuted(bool muted)
{
	m_captureSession.audioInput()->setMuted(muted);
}

void MainWindow::takeImage()
{
	m_isCapturingImage = true;
	m_imageCapture->captureToFile();
}

void MainWindow::displayCaptureError(int id, const QImageCapture::Error error,
								 const QString &errorString)
{
	Q_UNUSED(id);
	Q_UNUSED(error);
	QMessageBox::warning(this, tr("Image Capture Error"), errorString);
	m_isCapturingImage = false;
}

void MainWindow::startCamera()
{
	m_camera->start();
}

void MainWindow::stopCamera()
{
	m_camera->stop();
}

void MainWindow::updateCaptureMode()
{
	int tabIndex = ui->captureWidget->currentIndex();
	m_doImageCapture = (tabIndex == 0);
}

void MainWindow::updateCameraActive(bool active)
{
	if (active) {
		ui->actionStartCamera->setEnabled(false);
		ui->actionStopCamera->setEnabled(true);
		ui->captureWidget->setEnabled(true);
		ui->actionSettings->setEnabled(true);
	} else {
		ui->actionStartCamera->setEnabled(true);
		ui->actionStopCamera->setEnabled(false);
		ui->captureWidget->setEnabled(false);
		ui->actionSettings->setEnabled(false);
	}
}

void MainWindow::updateRecorderState(QMediaRecorder::RecorderState state)
{
	switch (state) {
	case QMediaRecorder::StoppedState:
		ui->recordButton->setEnabled(true);
		ui->pauseButton->setEnabled(true);
		ui->stopButton->setEnabled(false);
		ui->metaDataButton->setEnabled(true);
		break;
	case QMediaRecorder::PausedState:
		ui->recordButton->setEnabled(true);
		ui->pauseButton->setEnabled(false);
		ui->stopButton->setEnabled(true);
		ui->metaDataButton->setEnabled(false);
		break;
	case QMediaRecorder::RecordingState:
		ui->recordButton->setEnabled(false);
		ui->pauseButton->setEnabled(true);
		ui->stopButton->setEnabled(true);
		ui->metaDataButton->setEnabled(false);
		break;
	}
}

void MainWindow::displayRecorderError()
{
	if (m_mediaRecorder->error() != QMediaRecorder::NoError)
		QMessageBox::warning(this, tr("Capture Error"), m_mediaRecorder->errorString());
}

void MainWindow::displayCameraError()
{
	if (m_camera->error() != QCamera::NoError)
		QMessageBox::warning(this, tr("Camera Error"), m_camera->errorString());
}

void MainWindow::updateCameraDevice(QAction *action)
{
	setCamera(qvariant_cast<QCameraDevice>(action->data()));
}

void MainWindow::displayViewfinder()
{
	ui->stackedWidget->setCurrentIndex(0);
}

void MainWindow::displayCapturedImage()
{
	ui->stackedWidget->setCurrentIndex(1);
}

void MainWindow::readyForCapture(bool ready)
{
	ui->takeImageButton->setEnabled(ready);
}

void MainWindow::imageSaved(int id, const QString &fileName)
{
	Q_UNUSED(id);
	ui->statusbar->showMessage(tr("Captured \"%1\"").arg(QDir::toNativeSeparators(fileName)));

	m_isCapturingImage = false;
	if (m_applicationExiting)
		close();
}

void MainWindow::closeEvent(QCloseEvent *event)
{
	if (m_isCapturingImage) {
		setEnabled(false);
		m_applicationExiting = true;
		event->ignore();
	} else {
		event->accept();
	}
}

void MainWindow::updateCameras()
{
	ui->menuDevices->clear();
	const QList<QCameraDevice> availableCameras = QMediaDevices::videoInputs();
	for (const QCameraDevice &cameraDevice : availableCameras) {
		QAction *videoDeviceAction = new QAction(cameraDevice.description(), videoDevicesGroup);
		videoDeviceAction->setCheckable(true);
		videoDeviceAction->setData(QVariant::fromValue(cameraDevice));
		if (cameraDevice == QMediaDevices::defaultVideoInput())
			videoDeviceAction->setChecked(true);

		ui->menuDevices->addAction(videoDeviceAction);
	}
}

void MainWindow::showMetaDataDialog()
{
	if (!m_metaDataDialog)
		m_metaDataDialog = new MetaDataDialog(this);
	m_metaDataDialog->setAttribute(Qt::WA_DeleteOnClose, false);
	if (m_metaDataDialog->exec() == QDialog::Accepted)
		saveMetaData();
}

void MainWindow::saveMetaData()
{
	QMediaMetaData data;
	for (int i = 0; i < QMediaMetaData::NumMetaData; i++) {
		QString val = m_metaDataDialog->m_metaDataFields[i]->text();
		if (!val.isEmpty()) {
			const auto key = static_cast<QMediaMetaData::Key>(i);
			switch (key) {
			case QMediaMetaData::CoverArtImage: {
				QImage coverArt(val);
				data.insert(key, coverArt);
				break;
			}
			case QMediaMetaData::ThumbnailImage: {
				QImage thumbnail(val);
				data.insert(key, thumbnail);
				break;
			}
			case QMediaMetaData::Date: {
				QDateTime date = QDateTime::fromString(val);
				data.insert(key, date);
				break;
			}
			case QMediaMetaData::HasHdrContent:
				break;
			default:
				data.insert(key, val);
			}
		}
	}
	m_mediaRecorder->setMetaData(data);
}

void MainWindow::onFrame(const QVideoFrame &frame)
{
    if (!_tchat.canSendVideo()) return;

    QVideoFrame copy(frame);
    if (!copy.map(QVideoFrame::ReadOnly))
        return;

    // traiter l'image
    QImage image = copy.toImage().scaled(800, 600, Qt::KeepAspectRatio);

    if (image.isNull())
        return;

    copy.unmap();
	_videoEncodeur.encode(440, 320);
    QByteArray payload;
    QBuffer buffer(&payload);

    buffer.open(QIODevice::WriteOnly);

    image.save(&buffer, "JPEG", 75);
    QByteArray packet;
    QDataStream ds(&packet, QIODevice::WriteOnly);

	ds << _tchat.uuid();
	ds << payload;

    _tchat.sendVideoPacket(packet);
}