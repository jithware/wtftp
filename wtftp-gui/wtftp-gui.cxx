// generated by Fast Light User Interface Designer (fluid) version 1.0305

#include "wtftp-gui.h"

Fl_Double_Window *wtftp_window=(Fl_Double_Window *)0;

Fl_Input *user_input=(Fl_Input *)0;

Fl_Output *received_text=(Fl_Output *)0;

Fl_Double_Window* make_window() {
  { wtftp_window = new Fl_Double_Window(285, 205, "wtftp-gui");
    wtftp_window->callback((Fl_Callback*)callback_window_closing);
    { user_input = new Fl_Input(5, 175, 210, 25);
    } // Fl_Input* user_input
    { received_text = new Fl_Output(5, 5, 275, 165);
    } // Fl_Output* received_text
    { Fl_Button* o = new Fl_Button(220, 175, 60, 25, "send");
      o->callback((Fl_Callback*)callback_button);
    } // Fl_Button* o
    wtftp_window->end();
  } // Fl_Double_Window* wtftp_window
  return wtftp_window;
}

void callback_button( Fl_Widget* widg, void* userdata ) {
  std::cout << "button click\n";
  char const* text = user_input->value();
  // received_text->value( text );
  
  //initialize
  if (wtftp_init("wlp0s19f2u4") == -1) // TODO: provide user input for interface
  {
  	std::cerr << "error occurred\n";
  	return;
  }
  
  //send ping to the world
  wtftp_send_ping();
  
  //send out text from input
  wtftp_send_text(text);
}

void callback_window_closing( Fl_Widget* widg, void* userdata ) {
  std::cout << "Exiting the program\n"; 
  wtftp_window->hide();
}

int main(int argc, char **argv) {
  Fl_Window* win = make_window();
  win->show();
  return Fl::run();
}
