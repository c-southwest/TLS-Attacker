/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.data;

import de.rub.nds.tlsattacker.core.layer.context.LayerContext;

/**
 * @param <T> The Object that should be Handled
 */
public abstract class Handler<T extends DataContainer<? extends LayerContext>> {

    public abstract void adjustContext(T container);
}
