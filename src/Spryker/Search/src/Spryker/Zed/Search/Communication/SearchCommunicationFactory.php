<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Search\Communication;

use Spryker\Zed\Kernel\Communication\AbstractCommunicationFactory;
use Spryker\Zed\Search\Communication\Table\SearchTable;

/**
 * @method \Spryker\Zed\Search\SearchConfig getConfig()
 * @method \Spryker\Zed\Search\Business\SearchFacadeInterface getFacade()
 */
class SearchCommunicationFactory extends AbstractCommunicationFactory
{
    /**
     * @return \Spryker\Zed\Search\Communication\Table\SearchTable
     */
    public function createSearchTable()
    {
        return new SearchTable($this->getFacade());
    }

    /**
     * @return string
     */
    public function getElasticaDocumentType()
    {
        return $this->getConfig()->getElasticaDocumentType();
    }
}
