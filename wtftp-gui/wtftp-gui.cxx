// generated by Fast Light User Interface Designer (fluid) version 1.0305

#include "wtftp-gui.h"

Fl_Double_Window* make_window() {
  Fl_Double_Window* w;
  { Fl_Double_Window* o = new Fl_Double_Window(285, 205, "wtftp-gui");
    w = o; if (w) {/* empty */}
    o->end();
  } // Fl_Double_Window* o
  return w;
}

int main(int argc, char **argv) {
  Fl_Window* win = make_window();
  win->show();
  return Fl::run();
}
