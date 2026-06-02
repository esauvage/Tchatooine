#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "tchat.h"

#include <QSystemTrayIcon>

#include <QAudioInput>
#include <QCamera>
#include <QImageCapture>
#include <QMediaCaptureSession>
#include <QMediaDevices>
#include <QMediaMetaData>
#include <QMediaRecorder>

#include <memory>

class MetaDataDialog;

QT_BEGIN_NAMESPACE
namespace Ui {
class mainWindow;
}
class QActionGroup;
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
public slots:
	void saveMetaData();

protected:
    void keyPressEvent(QKeyEvent *event) override;
    void closeEvent(QCloseEvent *event) override;

private slots:
	void init();

	void setCamera(const QCameraDevice &cameraDevice);

	void startCamera();
	void stopCamera();

	void record();
	void pause();
	void stop();
	void setMuted(bool);

	void takeImage();
	void displayCaptureError(int, QImageCapture::Error, const QString &errorString);

	void configureCaptureSettings();
	void configureVideoSettings();
	void configureImageSettings();

	void displayRecorderError();
	void displayCameraError();

	void updateCameraDevice(QAction *action);

	void updateCameraActive(bool active);
	void updateCaptureMode();
	void updateRecorderState(QMediaRecorder::RecorderState state);

	void updateRecordTime();

	void processCapturedImage(int requestId, const QImage &img);

	void displayViewfinder();
	void displayCapturedImage();

	void readyForCapture(bool ready);
	void imageSaved(int id, const QString &fileName);

	void updateCameras();

	void showMetaDataDialog();
	void afficheMessage(QString message, bool isAncienMessage = false);
	void on_edtMessage_editingFinished();
	void on_cbxPair_currentIndexChanged(int index);
	void on_edtPseudo_editingFinished();
	void onClientConnected();
	void onServeurConnected();
	void affichePeers();
	void onVideoConnected();

    void onFrame(const QVideoFrame &frame);
    void processReadyRead();
    void onVideoConnection();

private:
	QActionGroup *videoDevicesGroup = nullptr;

	QMediaDevices m_devices;
	std::unique_ptr<QImageCapture> m_imageCapture;
	QMediaCaptureSession m_captureSession;
	std::unique_ptr<QCamera> m_camera;
	std::unique_ptr<QAudioInput> m_audioInput;
	std::unique_ptr<QMediaRecorder> m_mediaRecorder;
    std::unique_ptr<QVideoSink> _videoSink;

	bool m_isCapturingImage = false;
	bool m_applicationExiting = false;
	bool m_doImageCapture = true;

	MetaDataDialog *m_metaDataDialog = nullptr;

	Ui::mainWindow *ui;

    Tchat _tchat;
	QSystemTrayIcon _trayIcon;
    ServeurAvecUPNP _serveurVideo;
	QTcpSocket _clientVideo;
    QByteArray _videoBuffer;
    quint32 _imageSize;
};
#endif // MAINWINDOW_H
