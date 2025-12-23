"""
GUI Styling and Themes for Attack-Defense Framework
Author: Student Project
"""

# Color constants for consistent theming
COLORS = {
    # Status colors
    'success': '#4CAF50',
    'warning': '#FF9800',
    'error': '#F44336',
    'info': '#2196F3',
    
    # Risk level colors
    'critical': '#D32F2F',
    'high': '#F44336',
    'medium': '#FF9800',
    'low': '#4CAF50',
    'info': '#2196F3',
    
    # Theme colors
    'primary': '#0078D7',
    'primary_dark': '#106EBE',
    'primary_light': '#50B6FF',
    
    'secondary': '#6C757D',
    'secondary_dark': '#545B62',
    'secondary_light': '#8A9199',
    
    # Background colors
    'bg_dark': '#1E1E1E',
    'bg_medium': '#2D2D30',
    'bg_light': '#3E3E42',
    'bg_lighter': '#505050',
    
    # Text colors
    'text_primary': '#FFFFFF',
    'text_secondary': '#CCCCCC',
    'text_disabled': '#767676',
    
    # Border colors
    'border_dark': '#444',
    'border_medium': '#555',
    'border_light': '#666',
    
    # Special colors
    'exploit': '#FF5722',
    'defense': '#4CAF50',
    'scan': '#2196F3',
    'report': '#9C27B0'
}

# Font constants
FONTS = {
    'default': 'Segoe UI, Arial, sans-serif',
    'monospace': 'Consolas, Monaco, monospace',
    'title': 'Segoe UI Light, Arial, sans-serif'
}

# Complete QSS (Qt Style Sheet) for dark theme
STYLESHEET = f"""
/* ===== MAIN WINDOW ===== */
QMainWindow {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['text_primary']};
    font-family: {FONTS['default']};
    font-size: 10pt;
}}

/* ===== WIDGET BACKGROUNDS ===== */
QWidget {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['text_primary']};
    selection-background-color: {COLORS['primary']};
    selection-color: white;
}}

/* ===== TAB WIDGET ===== */
QTabWidget::pane {{
    border: 1px solid {COLORS['border_dark']};
    background-color: {COLORS['bg_medium']};
    border-radius: 4px;
    top: -1px;
}}

QTabWidget::tab-bar {{
    left: 5px;
}}

QTabBar::tab {{
    background-color: {COLORS['bg_light']};
    color: {COLORS['text_secondary']};
    padding: 8px 16px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    border: 1px solid {COLORS['border_dark']};
    border-bottom: none;
    min-width: 80px;
    font-weight: bold;
}}

QTabBar::tab:selected {{
    background-color: {COLORS['bg_medium']};
    color: {COLORS['text_primary']};
    border-bottom: 2px solid {COLORS['primary']};
}}

QTabBar::tab:hover:!selected {{
    background-color: {COLORS['bg_lighter']};
    color: {COLORS['text_primary']};
}}

QTabBar::tab:disabled {{
    background-color: {COLORS['bg_light']};
    color: {COLORS['text_disabled']};
}}

/* ===== BUTTONS ===== */
QPushButton {{
    background-color: {COLORS['primary']};
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
    font-weight: bold;
    font-size: 10pt;
}}

QPushButton:hover {{
    background-color: {COLORS['primary_dark']};
}}

QPushButton:pressed {{
    background-color: {COLORS['primary_dark']};
    padding-top: 9px;
    padding-bottom: 7px;
}}

QPushButton:disabled {{
    background-color: {COLORS['secondary']};
    color: {COLORS['text_disabled']};
}}

/* Special button types */
QPushButton[special="danger"] {{
    background-color: {COLORS['error']};
}}

QPushButton[special="danger"]:hover {{
    background-color: #D32F2F;
}}

QPushButton[special="success"] {{
    background-color: {COLORS['success']};
}}

QPushButton[special="success"]:hover {{
    background-color: #388E3C;
}}

QPushButton[special="warning"] {{
    background-color: {COLORS['warning']};
}}

QPushButton[special="warning"]:hover {{
    background-color: #F57C00;
}}

/* ===== LINE EDITS ===== */
QLineEdit {{
    background-color: {COLORS['bg_light']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border_medium']};
    border-radius: 3px;
    padding: 5px 8px;
    font-size: 10pt;
}}

QLineEdit:focus {{
    border: 1px solid {COLORS['primary']};
    background-color: {COLORS['bg_lighter']};
}}

QLineEdit:disabled {{
    background-color: {COLORS['bg_medium']};
    color: {COLORS['text_disabled']};
    border: 1px solid {COLORS['border_dark']};
}}

QLineEdit[error="true"] {{
    border: 2px solid {COLORS['error']};
}}

/* ===== COMBO BOXES ===== */
QComboBox {{
    background-color: {COLORS['bg_light']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border_medium']};
    border-radius: 3px;
    padding: 5px 8px;
    min-height: 20px;
}}

QComboBox:hover {{
    border: 1px solid {COLORS['primary_light']};
}}

QComboBox::drop-down {{
    border: none;
    padding-right: 10px;
}}

QComboBox::down-arrow {{
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 5px solid {COLORS['text_secondary']};
    width: 0;
    height: 0;
}}

QComboBox QAbstractItemView {{
    background-color: {COLORS['bg_light']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border_medium']};
    selection-background-color: {COLORS['primary']};
    selection-color: white;
    outline: none;
}}

/* ===== GROUP BOXES ===== */
QGroupBox {{
    border: 2px solid {COLORS['border_dark']};
    border-radius: 5px;
    margin-top: 20px;
    padding-top: 10px;
    font-weight: bold;
    font-size: 11pt;
    color: {COLORS['text_primary']};
    background-color: {COLORS['bg_medium']};
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 8px 0 8px;
    background-color: {COLORS['bg_medium']};
}}

/* ===== LABELS ===== */
QLabel {{
    color: {COLORS['text_primary']};
    font-size: 10pt;
}}

QLabel[heading="true"] {{
    font-size: 12pt;
    font-weight: bold;
    color: {COLORS['primary_light']};
}}

QLabel[subheading="true"] {{
    font-size: 11pt;
    font-weight: bold;
    color: {COLORS['text_secondary']};
}}

/* Status labels */
QLabel[status="success"] {{
    color: {COLORS['success']};
    font-weight: bold;
}}

QLabel[status="warning"] {{
    color: {COLORS['warning']};
    font-weight: bold;
}}

QLabel[status="error"] {{
    color: {COLORS['error']};
    font-weight: bold;
}}

QLabel[status="info"] {{
    color: {COLORS['info']};
    font-weight: bold;
}}

/* ===== TABLES ===== */
QTableView, QTableWidget {{
    background-color: {COLORS['bg_dark']};
    alternate-background-color: {COLORS['bg_medium']};
    color: {COLORS['text_primary']};
    gridline-color: {COLORS['border_dark']};
    border: 1px solid {COLORS['border_dark']};
    border-radius: 3px;
    font-size: 10pt;
    outline: none;
}}

QTableView::item, QTableWidget::item {{
    padding: 4px;
}}

QTableView::item:selected, QTableWidget::item:selected {{
    background-color: {COLORS['primary']};
    color: white;
}}

QHeaderView::section {{
    background-color: {COLORS['bg_light']};
    color: {COLORS['text_primary']};
    padding: 5px;
    border: 1px solid {COLORS['border_dark']};
    font-weight: bold;
    font-size: 10pt;
}}

QHeaderView::section:checked {{
    background-color: {COLORS['primary_dark']};
}}

/* ===== TREE VIEWS ===== */
QTreeView, QTreeWidget {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border_dark']};
    border-radius: 3px;
    font-size: 10pt;
    outline: none;
}}

QTreeView::item, QTreeWidget::item {{
    padding: 4px;
}}

QTreeView::item:selected, QTreeWidget::item:selected {{
    background-color: {COLORS['primary']};
    color: white;
}}

QTreeView::item:hover, QTreeWidget::item:hover {{
    background-color: {COLORS['bg_light']};
}}

/* ===== TEXT EDITS ===== */
QTextEdit, QPlainTextEdit {{
    background-color: {COLORS['bg_light']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border_medium']};
    border-radius: 3px;
    font-family: {FONTS['monospace']};
    font-size: 10pt;
    selection-background-color: {COLORS['primary']};
}}

QTextEdit:focus, QPlainTextEdit:focus {{
    border: 1px solid {COLORS['primary']};
}}

QTextEdit[readonly="true"], QPlainTextEdit[readonly="true"] {{
    background-color: {COLORS['bg_medium']};
    color: {COLORS['text_secondary']};
}}

/* ===== PROGRESS BARS ===== */
QProgressBar {{
    border: 1px solid {COLORS['border_medium']};
    border-radius: 3px;
    text-align: center;
    color: {COLORS['text_primary']};
    background-color: {COLORS['bg_medium']};
    font-size: 10pt;
}}

QProgressBar::chunk {{
    background-color: {COLORS['primary']};
    border-radius: 3px;
    width: 10px;
}}

QProgressBar::chunk[critical="true"] {{
    background-color: {COLORS['critical']};
}}

QProgressBar::chunk[warning="true"] {{
    background-color: {COLORS['warning']};
}}

/* ===== SCROLL BARS ===== */
QScrollBar:vertical {{
    border: none;
    background-color: {COLORS['bg_medium']};
    width: 12px;
    margin: 0px;
    border-radius: 6px;
}}

QScrollBar::handle:vertical {{
    background-color: {COLORS['bg_lighter']};
    border-radius: 6px;
    min-height: 20px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {COLORS['secondary']};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    border: none;
    background: none;
}}

QScrollBar:horizontal {{
    border: none;
    background-color: {COLORS['bg_medium']};
    height: 12px;
    margin: 0px;
    border-radius: 6px;
}}

QScrollBar::handle:horizontal {{
    background-color: {COLORS['bg_lighter']};
    border-radius: 6px;
    min-width: 20px;
}}

QScrollBar::handle:horizontal:hover {{
    background-color: {COLORS['secondary']};
}}

/* ===== MENU BAR ===== */
QMenuBar {{
    background-color: {COLORS['bg_medium']};
    color: {COLORS['text_primary']};
    border-bottom: 1px solid {COLORS['border_dark']};
    padding: 4px;
}}

QMenuBar::item {{
    background-color: transparent;
    padding: 4px 10px;
    border-radius: 3px;
}}

QMenuBar::item:selected {{
    background-color: {COLORS['bg_light']};
}}

QMenuBar::item:pressed {{
    background-color: {COLORS['primary']};
}}

QMenu {{
    background-color: {COLORS['bg_medium']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border_dark']};
    padding: 4px;
}}

QMenu::item {{
    background-color: transparent;
    padding: 6px 20px 6px 20px;
}}

QMenu::item:selected {{
    background-color: {COLORS['primary']};
    color: white;
}}

QMenu::separator {{
    height: 1px;
    background-color: {COLORS['border_dark']};
    margin: 4px 8px;
}}

/* ===== STATUS BAR ===== */
QStatusBar {{
    background-color: {COLORS['bg_medium']};
    color: {COLORS['text_secondary']};
    border-top: 1px solid {COLORS['border_dark']};
    font-size: 9pt;
}}

QStatusBar::item {{
    border: none;
}}

/* ===== CHECK BOXES & RADIO BUTTONS ===== */
QCheckBox, QRadioButton {{
    color: {COLORS['text_primary']};
    font-size: 10pt;
    spacing: 8px;
}}

QCheckBox::indicator, QRadioButton::indicator {{
    width: 16px;
    height: 16px;
}}

QCheckBox::indicator:unchecked {{
    border: 2px solid {COLORS['border_medium']};
    background-color: {COLORS['bg_light']};
    border-radius: 3px;
}}

QCheckBox::indicator:checked {{
    border: 2px solid {COLORS['primary']};
    background-color: {COLORS['primary']};
    border-radius: 3px;
    image: url(check.svg);
}}

QCheckBox::indicator:disabled {{
    border: 2px solid {COLORS['border_dark']};
    background-color: {COLORS['bg_medium']};
}}

QRadioButton::indicator:unchecked {{
    border: 2px solid {COLORS['border_medium']};
    background-color: {COLORS['bg_light']};
    border-radius: 9px;
}}

QRadioButton::indicator:checked {{
    border: 2px solid {COLORS['primary']};
    background-color: {COLORS['primary']};
    border-radius: 9px;
}}

/* ===== SPLITTERS ===== */
QSplitter::handle {{
    background-color: {COLORS['border_dark']};
}}

QSplitter::handle:horizontal {{
    width: 4px;
}}

QSplitter::handle:vertical {{
    height: 4px;
}}

QSplitter::handle:hover {{
    background-color: {COLORS['primary']};
}}

/* ===== LIST WIDGETS ===== */
QListWidget {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border_dark']};
    border-radius: 3px;
    font-size: 10pt;
    outline: none;
}}

QListWidget::item {{
    padding: 6px;
    border-bottom: 1px solid {COLORS['bg_medium']};
}}

QListWidget::item:selected {{
    background-color: {COLORS['primary']};
    color: white;
}}

QListWidget::item:hover:!selected {{
    background-color: {COLORS['bg_light']};
}}

/* ===== TOOL TIPS ===== */
QToolTip {{
    background-color: {COLORS['bg_light']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border_medium']};
    border-radius: 3px;
    padding: 4px;
    font-size: 9pt;
}}

/* ===== FRAMES ===== */
QFrame {{
    border: 1px solid {COLORS['border_dark']};
    border-radius: 3px;
}}

QFrame[shape="HLine"] {{
    max-height: 1px;
    border: none;
    background-color: {COLORS['border_dark']};
}}

QFrame[shape="VLine"] {{
    max-width: 1px;
    border: none;
    background-color: {COLORS['border_dark']};
}}

/* ===== DIALOGS ===== */
QDialog {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['text_primary']};
}}

QMessageBox {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['text_primary']};
}}

QMessageBox QLabel {{
    color: {COLORS['text_primary']};
    font-size: 10pt;
}}

/* ===== TOOLBARS ===== */
QToolBar {{
    background-color: {COLORS['bg_medium']};
    border-bottom: 1px solid {COLORS['border_dark']};
    spacing: 3px;
    padding: 2px;
}}

QToolBar::separator {{
    background-color: {COLORS['border_dark']};
    width: 1px;
    margin: 3px;
}}
"""

# Light theme alternative (optional)
LIGHT_STYLESHEET = f"""
QMainWindow {{
    background-color: #F5F5F5;
    color: #333333;
}}

QWidget {{
    background-color: #F5F5F5;
    color: #333333;
}}

QTabWidget::pane {{
    background-color: white;
    border: 1px solid #CCCCCC;
}}

QTabBar::tab {{
    background-color: #E0E0E0;
    color: #666666;
}}

QTabBar::tab:selected {{
    background-color: white;
    color: #333333;
}}

QPushButton {{
    background-color: #0078D7;
    color: white;
}}

QLineEdit {{
    background-color: white;
    color: #333333;
    border: 1px solid #CCCCCC;
}}

QComboBox {{
    background-color: white;
    color: #333333;
    border: 1px solid #CCCCCC;
}}

QGroupBox {{
    background-color: white;
    color: #333333;
    border: 2px solid #E0E0E0;
}}

QTableView, QTableWidget {{
    background-color: white;
    color: #333333;
}}

QTextEdit, QPlainTextEdit {{
    background-color: white;
    color: #333333;
}}
"""

def get_style_for_risk(risk_level):
    """Get CSS style for risk level indicators"""
    risk_styles = {
        'critical': f"""
            background-color: {COLORS['critical']};
            color: white;
            font-weight: bold;
            padding: 2px 8px;
            border-radius: 3px;
        """,
        'high': f"""
            background-color: {COLORS['high']};
            color: white;
            font-weight: bold;
            padding: 2px 8px;
            border-radius: 3px;
        """,
        'medium': f"""
            background-color: {COLORS['warning']};
            color: black;
            font-weight: bold;
            padding: 2px 8px;
            border-radius: 3px;
        """,
        'low': f"""
            background-color: {COLORS['low']};
            color: white;
            font-weight: bold;
            padding: 2px 8px;
            border-radius: 3px;
        """,
        'info': f"""
            background-color: {COLORS['info']};
            color: white;
            font-weight: bold;
            padding: 2px 8px;
            border-radius: 3px;
        """
    }
    return risk_styles.get(risk_level.lower(), '')

def get_status_style(status):
    """Get style for status indicators"""
    status_styles = {
        'success': f"color: {COLORS['success']}; font-weight: bold;",
        'warning': f"color: {COLORS['warning']}; font-weight: bold;",
        'error': f"color: {COLORS['error']}; font-weight: bold;",
        'info': f"color: {COLORS['info']}; font-weight: bold;",
        'pending': f"color: {COLORS['warning']}; font-weight: bold;",
        'completed': f"color: {COLORS['success']}; font-weight: bold;",
        'failed': f"color: {COLORS['error']}; font-weight: bold;"
    }
    return status_styles.get(status, '')

def get_button_style(button_type='default'):
    """Get style for different button types"""
    button_styles = {
        'primary': f"""
            QPushButton {{
                background-color: {COLORS['primary']};
                color: white;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['primary_dark']};
            }}
        """,
        'danger': f"""
            QPushButton {{
                background-color: {COLORS['error']};
                color: white;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #D32F2F;
            }}
        """,
        'success': f"""
            QPushButton {{
                background-color: {COLORS['success']};
                color: white;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #388E3C;
            }}
        """,
        'warning': f"""
            QPushButton {{
                background-color: {COLORS['warning']};
                color: black;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #F57C00;
            }}
        """
    }
    return button_styles.get(button_type, '')