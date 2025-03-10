/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl.DataContainerFilters;

import de.rub.nds.tlsattacker.core.layer.DataContainerFilter;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;

public class GenericDataContainerFilter extends DataContainerFilter {

    private final Class<? extends DataContainer> filteredClass;

    public GenericDataContainerFilter(Class<? extends DataContainer> filteredClass) {
        this.filteredClass = filteredClass;
    }

    @Override
    public boolean filterApplies(DataContainer container) {
        return filteredClass.equals(container.getClass());
    }
}
