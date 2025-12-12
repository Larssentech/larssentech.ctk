// (c) 2005-2022 AVANZ.IO
// (c) 2008 Jeffrey J Cerasuolo

package org.larssentech.CTK.ui.gui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.File;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.UIManager;
import javax.swing.border.TitledBorder;

import org.larssentech.CTK.driver.StandAloneApi;
import org.larssentech.CTK.settings.CTKSettings;
import org.larssentech.CTK.settings.RSAPathBundle;
import org.larssentech.lib.basiclib.io.text.SaveToFile;
import org.larssentech.lib.basiclib.settings.SettingsExtractor;
import org.larssentech.lib.basiclib.settings.SettingsUpdater;
import org.larssentech.lib.basiclib.toolkit.StringManipulationToolkit;

public class NxCTK extends JFrame implements CTKSettings { // NO_UCD (use
															// default)

	private static String loc = "ES";

	public static void main(String[] args) {

		try {

			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		}
		catch (Exception ignored) {}

		// Must be the first thing we do
		RSAPathBundle.setOwnPKPath(OWN_PRI_K_ABS_PATH);
		RSAPathBundle.setOwnPUKPath(OWN_PUB_K_ABS_PATH);
		RSAPathBundle.setOwnKeyPairPath(OWN_KEYPAIR_ABS_PATH);
		RSAPathBundle.setCipherString("RSA");

		// For out contact library
		new File(CTKSettings.HOME_DIR + CTKSettings.SEP + "nxrsa_pub_key_lib").mkdir();
		new File(CTKSettings.HOME_DIR + CTKSettings.SEP + CTKSettings.CTK_HOME).mkdir();
		new File(CTKSettings.HOME_DIR + CTKSettings.SEP + CTKSettings.OWN_RSA_DIR).mkdir();

		r = new StandAloneApi();

		NxCTK gui = new NxCTK(SETTINGS_PATH);
		gui.setSize(440, 480);
		gui.setResizable(false);
		gui.setLocation(50, 50);
		gui.setVisible(true);

	}

	private static StandAloneApi r;
	private boolean blowfishWorking = false;

	private boolean combosNeedSync = true;
	private NxCTKLangMap lang = new NxCTKLangMap();

	private BorderLayout borderLayout1 = new BorderLayout();
	private JLabel statusBar = new JLabel();
	private JMenuBar nxCTKMenuBar = new JMenuBar();
	private JMenu fileMenu = new JMenu();
	private JMenuItem exportPublicKeyMenuItem = new JMenuItem();
	private JMenu contactsMenu = new JMenu();
	private JMenuItem addContactMenuItem = new JMenuItem();
	private JTabbedPane nxEncTabbedPane = new JTabbedPane();
// TODO Remove unused code found by UCDetector
// 	TitledBorder titledBorder1;
// TODO Remove unused code found by UCDetector
// 	Border border1;
// TODO Remove unused code found by UCDetector
// 	Border border2;
// TODO Remove unused code found by UCDetector
// 	TitledBorder titledBorder2;
// TODO Remove unused code found by UCDetector
// 	Border border3;
	private JPanel fileEncryptPane = new JPanel();
	private JPanel fileDecryptPane = new JPanel();
	private TitledBorder titledBorder3;
	private JPanel encryptFilePanel = new JPanel();
// TODO Remove unused code found by UCDetector
// 	Border border4;
	private TitledBorder titledBorder4;
	private JLabel jLabel3 = new JLabel();
	private JLabel jLabel4 = new JLabel();
	private JButton browseFileToEncryptButton = new JButton();
	private JTextField fileToEncryptField = new JTextField();
	private JComboBox contactCombo1 = new JComboBox();
	private JTextArea encryptedFilesArea = new JTextArea();
	private JProgressBar encProgress = new JProgressBar();
	private JLabel jLabel6 = new JLabel();
	private JButton encryptFilesButton = new JButton();
	private JButton browseFileToDecryptButton = new JButton();
	private JButton decryptFilesButton = new JButton();
	private JLabel jLabel7 = new JLabel();
	private JLabel jLabel8 = new JLabel();
	private JTextField fileToDecryptField = new JTextField();
	private JProgressBar decProgress = new JProgressBar();
	private JTextArea decryptedFilesArea = new JTextArea();
	private JPanel decryptFilePanel = new JPanel();
	private JLabel encStatus = new JLabel();
	private JLabel decStatus = new JLabel();
	private JMenuItem exitMenuItem = new JMenuItem();

	private TitledBorder titledBorder6;

	private JButton jButton1 = new JButton();

	private NxCTK(String settingsPath) {

		// Before we load the GUI
		NxCTK.checkLanguage(settingsPath);

		// Load GUI
		try {

			jbInit();
		}
		catch (Exception e) {

			e.printStackTrace();
		}

		// Load users
		this.doLoadContactsToCombo();
		this.setTitle(CTKSettings.VERSION);
	}

	private void jbInit() throws Exception {

		this.titledBorder3 = new TitledBorder(BorderFactory.createEmptyBorder(), "");
		this.titledBorder4 = new TitledBorder(BorderFactory.createEtchedBorder(Color.white, new Color(148, 145, 140)), this.lang.getInLang("DEC_FILE_PANE_TITLE", loc));
		this.titledBorder6 = new TitledBorder(BorderFactory.createEtchedBorder(Color.white, new Color(148, 145, 140)), this.lang.getInLang("ENC_FILE_PANE_TITLE", loc));
		this.statusBar.setFont(new Font("Dialog", 0, 10));
		this.getContentPane().setLayout(this.borderLayout1);
		this.setDefaultCloseOperation(EXIT_ON_CLOSE);
		this.setJMenuBar(this.nxCTKMenuBar);
		this.setSize(new Dimension(450, 487));
		this.fileMenu.setText(this.lang.getInLang("FILE_MENU_TITLE", loc));
		this.exportPublicKeyMenuItem.setText(this.lang.getInLang("EXPORT_MY_PUB_KEY", loc));
		this.exportPublicKeyMenuItem.addActionListener(new RSACipherGUI_exportPublicKeyMenuItem_actionAdapter(this));
		this.contactsMenu.setText(this.lang.getInLang("CONTACTS_MENU_TITLE", loc));
		this.addContactMenuItem.setText(this.lang.getInLang("ADD_CONTACT_MENU_ITEM", loc));
		this.addContactMenuItem.addActionListener(new RSACipherGUI_addContactMenuItem_actionAdapter(this));
		this.fileDecryptPane.setLayout(null);
		this.fileEncryptPane.setLayout(null);
		this.fileEncryptPane.setBorder(this.titledBorder3);
		this.encryptFilePanel.setBorder(this.titledBorder6);
		this.encryptFilePanel.setBounds(new Rectangle(9, 7, 410, 372));
		this.encryptFilePanel.setLayout(null);
		this.jLabel3.setText(this.lang.getInLang("SELECT_FILE_TO_ENCRYPT_LABEL", loc));
		this.jLabel3.setBounds(new Rectangle(20, 31, 371, 14));
		this.jLabel4.setBounds(new Rectangle(20, 103, 372, 14));
		this.jLabel4.setText(this.lang.getInLang("SELECT_RECIP_ENC_LABEL", loc));
		this.browseFileToEncryptButton.setBounds(new Rectangle(301, 61, 92, 24));
		this.browseFileToEncryptButton.setText(this.lang.getInLang("BROWSE", loc));
		this.browseFileToEncryptButton.addActionListener(new NxRSAGUI_browseFileToEncryptButton_actionAdapter(this));
		this.fileToEncryptField.setEditable(false);
		this.fileToEncryptField.setBounds(new Rectangle(20, 60, 271, 27));
		this.contactCombo1.addItemListener(new RSACipherGUI_contactCombo1_itemAdapter(this));
		this.contactCombo1.setBounds(new Rectangle(20, 132, 246, 23));
		this.encryptedFilesArea.setFont(new Font("Dialog", 0, 9));
		this.encryptedFilesArea.setBorder(BorderFactory.createEtchedBorder());
		this.encryptedFilesArea.setEditable(false);
		this.encryptedFilesArea.setText("");
		this.encryptedFilesArea.setBounds(new Rectangle(20, 239, 371, 70));
		this.encProgress.setBounds(new Rectangle(131, 344, 148, 14));
		this.jLabel6.setText(this.lang.getInLang("ENCRYPT_LABEL", loc));
		this.jLabel6.setBounds(new Rectangle(20, 170, 176, 14));
		this.encryptFilesButton.setBounds(new Rectangle(20, 199, 99, 24));
		this.encryptFilesButton.setText(this.lang.getInLang("ENCRYPT_FILE_BUTTON", loc));
		this.encryptFilesButton.addActionListener(new NxRSAGUI_encryptFilesButton_actionAdapter(this));
		this.browseFileToDecryptButton.addActionListener(new NxRSAGUI_browseFileToDecryptButton_actionAdapter(this));
		this.browseFileToDecryptButton.setText(this.lang.getInLang("BROWSE", loc));
		this.browseFileToDecryptButton.setBounds(new Rectangle(301, 61, 92, 24));
		this.decryptFilesButton.addActionListener(new NxRSAGUI_decryptFilesButton_actionAdapter(this));
		this.decryptFilesButton.setText(this.lang.getInLang("DECRYPT_BUTTON", loc));
		this.decryptFilesButton.setBounds(new Rectangle(21, 132, 114, 24));
		this.jLabel7.setBounds(new Rectangle(20, 103, 127, 14));
		this.jLabel7.setText(this.lang.getInLang("DECRYPT_LABEL", loc));
		this.jLabel8.setBounds(new Rectangle(20, 31, 371, 14));
		this.jLabel8.setText(this.lang.getInLang("SELECT_FILE_TO_DECRYPT_LABEL", loc));
		this.fileToDecryptField.setEditable(false);
		this.fileToDecryptField.setBounds(new Rectangle(20, 60, 271, 27));
		this.decProgress.setBounds(new Rectangle(131, 344, 148, 14));
		this.decryptedFilesArea.setBounds(new Rectangle(20, 171, 371, 139));
		this.decryptedFilesArea.setText("");
		this.decryptedFilesArea.setEditable(false);
		this.decryptedFilesArea.setBorder(BorderFactory.createEtchedBorder());
		this.decryptedFilesArea.setFont(new Font("Dialog", 0, 9));
		this.decryptFilePanel.setLayout(null);
		this.decryptFilePanel.setBounds(new Rectangle(9, 7, 410, 372));
		this.decryptFilePanel.setBorder(this.titledBorder4);
		this.encStatus.setHorizontalAlignment(SwingConstants.CENTER);
		this.encStatus.setText(this.lang.getInLang("CRIPT_ENGINE_INACTIVE_MSG", loc));
		this.encStatus.setBounds(new Rectangle(28, 323, 354, 14));
		this.decStatus.setBounds(new Rectangle(28, 323, 354, 14));
		this.decStatus.setText(this.lang.getInLang("CRIPT_ENGINE_INACTIVE_MSG", loc));
		this.decStatus.setHorizontalAlignment(SwingConstants.CENTER);
		this.exitMenuItem.setText(this.lang.getInLang("EXIT_MENU_ITEM", loc));
		this.exitMenuItem.addActionListener(new NxCryptoToolKitGUI_exitMenuItem_actionAdapter(this));

		this.jButton1.setBounds(new Rectangle(18, 304, 105, 24));
		this.jButton1.setText(this.lang.getInLang("RESET_BUTTON", loc));
		this.jButton1.addActionListener(new NxCryptoToolKitGUI_jButton1_actionAdapter(this));
		this.getContentPane().add(this.statusBar, BorderLayout.SOUTH);
		this.getContentPane().add(this.nxEncTabbedPane, BorderLayout.CENTER);
		this.nxCTKMenuBar.add(this.fileMenu);
		this.nxCTKMenuBar.add(this.contactsMenu);
		this.fileMenu.add(this.exportPublicKeyMenuItem);
		this.fileMenu.addSeparator();
		this.fileMenu.add(this.exitMenuItem);
		this.contactsMenu.add(this.addContactMenuItem);
		String title0 = this.lang.getInLang("ENC_FILE_TAB_LABEL", loc);
		String title1 = this.lang.getInLang("DEC_FILE_TAB_LABEL", loc);
		this.lang.getInLang("ENC_EMAIL_TAB_LABEL", loc);

		this.nxEncTabbedPane.add(this.fileEncryptPane, title0);

		this.fileEncryptPane.add(this.encryptFilePanel, null);
		this.encryptFilePanel.add(this.jLabel3, null);
		this.encryptFilePanel.add(this.fileToEncryptField, null);
		this.nxEncTabbedPane.add(this.fileDecryptPane, title1);
		this.fileDecryptPane.add(this.decryptFilePanel, null);
		this.decryptFilePanel.add(this.jLabel8, null);
		this.decryptFilePanel.add(this.fileToDecryptField, null);
		this.decryptFilePanel.add(this.browseFileToDecryptButton, null);
		this.encryptFilePanel.add(this.encProgress, null);
		this.encryptFilePanel.add(this.jLabel4, null);
		this.encryptFilePanel.add(this.contactCombo1, null);
		this.encryptFilePanel.add(this.jLabel6, null);
		this.encryptFilePanel.add(this.encryptFilesButton, null);
		this.encryptFilePanel.add(this.encryptedFilesArea, null);
		this.encryptFilePanel.add(this.browseFileToEncryptButton, null);
		this.encryptFilePanel.add(this.encStatus, null);
		this.decryptFilePanel.add(this.jLabel7, null);
		this.decryptFilePanel.add(this.decryptFilesButton, null);
		this.decryptFilePanel.add(this.decryptedFilesArea, null);
		this.decryptFilePanel.add(this.decProgress, null);
		this.decryptFilePanel.add(this.decStatus, null);

	}

	public static void checkLanguage(String settingsPath) {

		String language = SettingsExtractor.extractThis4(settingsPath, "language");

		if (language.length() == 0) {

			SettingsUpdater.updateLine(settingsPath, "language", System.getProperty("user.language"));
		}

		language = SettingsExtractor.extractThis4(settingsPath, "language");
		NxCTK.loc = language;
	}

	private class BlowfishEncryptProgressGUIUpdate extends Thread {
		public void run() {

			NxCTK.r.resetBlowfishCounters();

			long total = 0;

			while (NxCTK.this.blowfishWorking) {

				long progress = StandAloneApi.getBlowfishProgress();

				total = NxCTK.r.getBlowfishTotal();

				NxCTK.this.encStatus.setEnabled(true);
				NxCTK.this.encProgress.setEnabled(true);

				NxCTK.this.encStatus.setText(NxCTK.this.lang.getInLang("ENC_PROGRESS_MSG1", loc) + StringManipulationToolkit.insertThousandSeparator("" + progress)
						+ NxCTK.this.lang.getInLang("ENC_PROGRESS_MSG2", loc) + StringManipulationToolkit.insertThousandSeparator("" + total) + NxCTK.this.lang.getInLang("ENC_PROGRESS_MSG3", loc));
				NxCTK.this.encProgress.setMaximum(100);
				NxCTK.this.encProgress.setStringPainted(true);
				progress = total == 0 ? 0 : 100 * progress / total;
				NxCTK.this.encProgress.setValue((int) progress);

				try {

					Thread.sleep(50);
				}
				catch (InterruptedException ignored) {}

			}
			NxCTK.this.encStatus.setText(
					NxCTK.this.lang.getInLang("ENC_PROC_COMPLETE1", loc) + StringManipulationToolkit.insertThousandSeparator("" + total) + NxCTK.this.lang.getInLang("ENC_PROC_COMPLETE2", loc));
			NxCTK.this.encProgress.setValue(100);
		}
	}

	private class BlowfishDecryptProgressGUIUpdate extends Thread {
		public void run() {

			NxCTK.r.resetBlowfishCounters();
			long total = 0;

			while (NxCTK.this.blowfishWorking) {

				long progress = StandAloneApi.getBlowfishProgress();
				total = NxCTK.r.getBlowfishTotal();
				NxCTK.this.decStatus.setEnabled(true);
				NxCTK.this.decProgress.setEnabled(true);
				NxCTK.this.decStatus.setText(NxCTK.this.lang.getInLang("DEC_PROGRESS_MSG1", loc) + StringManipulationToolkit.insertThousandSeparator("" + progress)
						+ NxCTK.this.lang.getInLang("DEC_PROGRESS_MSG2", loc) + StringManipulationToolkit.insertThousandSeparator("" + total) + NxCTK.this.lang.getInLang("DEC_PROGRESS_MSG3", loc));
				NxCTK.this.decProgress.setMaximum(100);
				NxCTK.this.decProgress.setStringPainted(true);
				progress = total == 0 ? 0 : progress * 100 / total;
				NxCTK.this.decProgress.setValue((int) progress);

				try {

					Thread.sleep(50);
				}
				catch (InterruptedException ignored) {}

			}
			NxCTK.this.decStatus.setText(NxCTK.this.lang.getInLang("DEC_PROC_COMPLETE1", loc) + StringManipulationToolkit.insertThousandSeparator("" + NxCTK.r.getBlowfishTotal())
					+ NxCTK.this.lang.getInLang("DEC_PROC_COMPLETE2", loc));
			NxCTK.this.decProgress.setValue(100);

			// Wait a bit and do a last refresh
			try {

				Thread.sleep(500);
			}
			catch (InterruptedException iE) {}
			NxCTK.this.decStatus.setText(NxCTK.this.lang.getInLang("DEC_PROC_COMPLETE1", loc) + StringManipulationToolkit.insertThousandSeparator("" + NxCTK.r.getBlowfishTotal())
					+ NxCTK.this.lang.getInLang("DEC_PROC_COMPLETE2", loc));
			NxCTK.this.decProgress.setValue(100);
		}
	}

	private void doReset() {

	}

	private void doBlowfishDecryption() {

		Thread dec = new Thread() {

			public void run() {

				if (NxCTK.this.fileToDecryptField.getText().length() > 0) {

					enableAllShit(false);
					NxCTK.this.blowfishWorking = true;
					new BlowfishDecryptProgressGUIUpdate().start();
					String[] resultingFiles = new String[] { "Error" };

					try {

						resultingFiles = NxCTK.r.decryptBlowfish(NxCTK.this.fileToDecryptField.getText());

					}

					catch (IllegalArgumentException e) {

						JOptionPane.showMessageDialog(null,
								NxCTK.this.lang.getInLang("CORRUPTED_FILE_ERROR_LINE1", loc) + "\n" + NxCTK.this.lang.getInLang("CORRUPTED_FILE_ERROR_LINE2", loc) + "\n"
										+ NxCTK.this.lang.getInLang("CORRUPTED_FILE_ERROR_LINE3", loc) + "\n\n" + e.toString() + "\n" + NxCTK.this.lang.getInLang("CORRUPTED_FILE_ERROR_LINE4", loc),
								"AVANZ.IO", JOptionPane.ERROR_MESSAGE);
						e.printStackTrace();
					}

					NxCTK.this.blowfishWorking = false;
					enableAllShit(true);

					if (resultingFiles.length > 0) { for (int i = 0; i < resultingFiles.length; i++) NxCTK.this.decryptedFilesArea.append(resultingFiles[i] + "\n"); }
				}
			}
		};
		dec.start();
	}

	public void doBlowfishEncryption() {

		Thread enc = new Thread() {
			public void run() {

				if (NxCTK.this.fileToEncryptField.getText().length() > 0) {

					enableAllShit(false);
					NxCTK.this.blowfishWorking = true;
					new BlowfishEncryptProgressGUIUpdate().start();

					String[] resultingFiles = new String[] { "Error?" };

					try {

						resultingFiles = NxCTK.r.encryptBlowfish(NxCTK.this.fileToEncryptField.getText());
					}
					catch (Exception e) {

						JOptionPane.showMessageDialog(null, "ERROR:\n" + e.toString() + "\n" + NxCTK.this.lang.getInLang("CORRUPTED_FILE_ERROR_LINE4", loc), "AVANZ.IO", JOptionPane.ERROR_MESSAGE);
						e.printStackTrace();
					}

					NxCTK.this.blowfishWorking = false;
					enableAllShit(true);

					if (resultingFiles.length > 0) { for (int i = 0; i < resultingFiles.length; i++) NxCTK.this.encryptedFilesArea.append(resultingFiles[i] + "\n"); }
				}
			}
		};
		enc.start();
	}

	private void doExportMyPUK(String ownPUKPath) {

		JFileChooser jFC = new JFileChooser();
		jFC.setSelectedFile(new File("NX_RSA_PUB_KEY.asc"));

		if (jFC.showSaveDialog(this) == 0) {

			new SaveToFile();
			SaveToFile.saveToFile(jFC.getSelectedFile().getAbsolutePath(), new String[] { StandAloneApi.exportMyPublicKey(ownPUKPath) }, false);

		}
	}

	void enableAllShit(boolean b) {

		this.nxCTKMenuBar.setEnabled(b);
		this.fileMenu.setEnabled(b);
		this.contactsMenu.setEnabled(b);
		this.nxEncTabbedPane.setEnabled(b);

		this.nxEncTabbedPane.setEnabled(b);

		Component[] allComponents = this.decryptFilePanel.getComponents();
		for (int i = 0; i < allComponents.length; i++) allComponents[i].setEnabled(b);
		this.nxEncTabbedPane.setEnabled(b);
		allComponents = this.encryptFilePanel.getComponents();
		for (int i = 0; i < allComponents.length; i++) allComponents[i].setEnabled(b);
	}

	private void doAddContact(String otherUsersPath) {

		String userEmail = JOptionPane.showInputDialog(null, "Please type the email address of the new contact. This will be used as his identification.", "Step 1 of 2", JOptionPane.QUESTION_MESSAGE);

		if (userEmail != null && userEmail.length() > 0 && userEmail.indexOf(".") > 0 && userEmail.indexOf("@") > 0) {

			JFileChooser jFc = new JFileChooser();
			jFc.setDialogTitle("Step 2 of 2 - Open New Contact Public Key (BASE64)");

			if (jFc.showOpenDialog(this) == 0) { StandAloneApi.addContact(userEmail, jFc.getSelectedFile().getAbsolutePath(), otherUsersPath); }
		}
		else JOptionPane.showMessageDialog(null, "Bad email address. Operation cancelled", "Error", JOptionPane.ERROR_MESSAGE);
		this.doLoadContactsToCombo();
	}

	private void doLoadContactsToCombo() {

		this.combosNeedSync = false;
		this.contactCombo1.removeAllItems();

		String[] contacts = StandAloneApi.getContacts();

		for (int i = 0; i < contacts.length; i++) this.contactCombo1.addItem(contacts[i]);

		this.combosNeedSync = true;

		// Load the public key for the contact showing
		if (this.contactCombo1.getItemCount() > 0) NxCTK.r.loadPublicKeyForUser(this.contactCombo1.getSelectedItem().toString(), CTKSettings.OTHER_USERS_PUB_KEY_LIB);

	}

	void contactCombo1_itemStateChanged() {

		if (this.combosNeedSync) {

			if (this.contactCombo1.getItemCount() > 0) {

				String user = this.contactCombo1.getSelectedItem().toString();
				boolean b = NxCTK.r.loadPublicKeyForUser(user, CTKSettings.OTHER_USERS_PUB_KEY_LIB);
				if (b) this.statusBar.setText(this.lang.getInLang("USING_PUB_KEY_MSG", loc) + user);
			}
			this.combosNeedSync = false;

			this.combosNeedSync = true;
		}
	}

	void browseFileToEncryptButton_actionPerformed() {

		JFileChooser jFc = new JFileChooser();
		jFc.setDialogTitle(this.lang.getInLang("BROWSE_FILE_TO_ENCRYPT", loc));

		if (jFc.showOpenDialog(this) == 0) { this.fileToEncryptField.setText(jFc.getSelectedFile().getAbsolutePath()); }
	}

	void exportPublicKeyMenuItem_actionPerformed() {

		this.doExportMyPUK(CTKSettings.OWN_PUB_K_ABS_PATH);
	}

	void addContactMenuItem_actionPerformed() {

		this.doAddContact(CTKSettings.OTHER_USERS_PUB_KEY_LIB + CTKSettings.SEP);
	}

	void encryptFilesButton_actionPerformed() {

		this.doBlowfishEncryption();
	}

	void browseFileToDecryptButton_actionPerformed() {

		JFileChooser jFc = new JFileChooser();
		jFc.setDialogTitle(this.lang.getInLang("BROWSE_FILE_TO_DECRYPT", loc));

		if (jFc.showOpenDialog(this) == 0) this.fileToDecryptField.setText(jFc.getSelectedFile().getAbsolutePath());
	}

	void decryptFilesButton_actionPerformed() {

		this.doBlowfishDecryption();
	}

	static void exitMenuItem_actionPerformed() {

		System.exit(0);
	}

	void jButton1_actionPerformed() {

		this.doReset();
	}
}

class RSACipherGUI_exportPublicKeyMenuItem_actionAdapter implements ActionListener {
	private NxCTK adaptee;

	RSACipherGUI_exportPublicKeyMenuItem_actionAdapter(NxCTK adaptee) {

		this.adaptee = adaptee;
	}

	public void actionPerformed(ActionEvent e) {

		this.adaptee.exportPublicKeyMenuItem_actionPerformed();
	}
}

class RSACipherGUI_addContactMenuItem_actionAdapter implements ActionListener {
	private NxCTK adaptee;

	RSACipherGUI_addContactMenuItem_actionAdapter(NxCTK adaptee) {

		this.adaptee = adaptee;
	}

	public void actionPerformed(ActionEvent e) {

		this.adaptee.addContactMenuItem_actionPerformed();
	}
}

class NxRSAGUI_browseFileToEncryptButton_actionAdapter implements ActionListener {
	private NxCTK adaptee;

	NxRSAGUI_browseFileToEncryptButton_actionAdapter(NxCTK adaptee) {

		this.adaptee = adaptee;
	}

	public void actionPerformed(ActionEvent e) {

		this.adaptee.browseFileToEncryptButton_actionPerformed();
	}
}

class RSACipherGUI_contactCombo1_itemAdapter implements ItemListener {
	private NxCTK adaptee;

	RSACipherGUI_contactCombo1_itemAdapter(NxCTK adaptee) {

		this.adaptee = adaptee;
	}

	public void itemStateChanged(ItemEvent e) {

		this.adaptee.contactCombo1_itemStateChanged();
	}
}

class NxRSAGUI_encryptFilesButton_actionAdapter implements ActionListener {
	private NxCTK adaptee;

	NxRSAGUI_encryptFilesButton_actionAdapter(NxCTK adaptee) {

		this.adaptee = adaptee;
	}

	public void actionPerformed(ActionEvent e) {

		this.adaptee.encryptFilesButton_actionPerformed();
	}
}

class NxRSAGUI_browseFileToDecryptButton_actionAdapter implements ActionListener {
	private NxCTK adaptee;

	NxRSAGUI_browseFileToDecryptButton_actionAdapter(NxCTK adaptee) {

		this.adaptee = adaptee;
	}

	public void actionPerformed(ActionEvent e) {

		this.adaptee.browseFileToDecryptButton_actionPerformed();
	}
}

class NxRSAGUI_decryptFilesButton_actionAdapter implements ActionListener {
	private NxCTK adaptee;

	NxRSAGUI_decryptFilesButton_actionAdapter(NxCTK adaptee) {

		this.adaptee = adaptee;
	}

	public void actionPerformed(ActionEvent e) {

		this.adaptee.decryptFilesButton_actionPerformed();
	}
}

class NxCryptoToolKitGUI_exitMenuItem_actionAdapter implements ActionListener {

	NxCryptoToolKitGUI_exitMenuItem_actionAdapter(NxCTK adaptee) {

	}

	public void actionPerformed(ActionEvent e) {

		NxCTK.exitMenuItem_actionPerformed();
	}
}

class NxCryptoToolKitGUI_jButton1_actionAdapter implements ActionListener {
	private NxCTK adaptee;

	NxCryptoToolKitGUI_jButton1_actionAdapter(NxCTK adaptee) {

		this.adaptee = adaptee;
	}

	public void actionPerformed(ActionEvent e) {

		this.adaptee.jButton1_actionPerformed();
	}
}
