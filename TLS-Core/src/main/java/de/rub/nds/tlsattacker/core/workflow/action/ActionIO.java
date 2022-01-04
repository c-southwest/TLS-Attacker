/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.reflections.Reflections;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.*;
import java.util.Set;

public class ActionIO {

    private static final Logger LOGGER = LogManager.getLogger();

    private static JAXBContext context;

    private static synchronized JAXBContext getJAXBContext() throws JAXBException, IOException {
        if (context == null) {
            Reflections reflections = new Reflections("de.rub.nds.tlsattacker.core.workflow.action");
            Set<Class<? extends TlsAction>> classes = reflections.getSubTypesOf(TlsAction.class);
            Class<? extends TlsAction>[] classesArray = classes.toArray(new Class[classes.size()]);
            context = JAXBContext.newInstance(classesArray);
        }
        return context;
    }

    public static void write(File file, TlsAction action) throws FileNotFoundException, JAXBException, IOException {
        if (!file.exists()) {
            file.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(file);
        ActionIO.write(fos, action);
    }

    public static void write(OutputStream outputStream, TlsAction action) throws JAXBException, IOException {
        context = getJAXBContext();
        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        m.marshal(action, outputStream);
        outputStream.close();
    }

    public static TlsAction read(InputStream inputStream) throws JAXBException, IOException, XMLStreamException {
        context = getJAXBContext();
        Unmarshaller m = context.createUnmarshaller();
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);
        TlsAction action = (TlsAction) m.unmarshal(xsr);
        inputStream.close();
        return action;
    }

    public static TlsAction copyTlsAction(TlsAction tlsAction) throws JAXBException, IOException, XMLStreamException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        ActionIO.write(stream, tlsAction);
        stream.flush();
        TlsAction copiedAction = ActionIO.read(new ByteArrayInputStream(stream.toByteArray()));
        return copiedAction;
    }

    private ActionIO() {
    }
}
