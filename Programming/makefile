JFLAGS = -g
JC = javac
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
	server.java \
	AES.java \
	RSA.java \
	client1.java \
	client2.java 

default: classes

classes: $(CLASSES:.java=.class)

clean:
	$(RM) *.class
