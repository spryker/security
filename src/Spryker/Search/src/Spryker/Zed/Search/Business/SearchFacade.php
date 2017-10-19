<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Search\Business;

use Generated\Shared\Transfer\LocaleTransfer;
use Psr\Log\LoggerInterface;
use Spryker\Zed\Kernel\Business\AbstractFacade;
use Spryker\Zed\Search\Dependency\Plugin\PageMapInterface;

/**
 * @method \Spryker\Zed\Search\Business\SearchBusinessFactory getFactory()
 */
class SearchFacade extends AbstractFacade implements SearchFacadeInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Psr\Log\LoggerInterface $messenger
     *
     * @return void
     */
    public function install(LoggerInterface $messenger)
    {
        $this
            ->getFactory()
            ->createSearchInstaller($messenger)
            ->install();
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return int
     */
    public function getTotalCount()
    {
        return $this
            ->getFactory()
            ->createSearchIndexManager()
            ->getTotalCount();
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return array
     */
    public function getMetaData()
    {
        return $this
            ->getFactory()
            ->createSearchIndexManager()
            ->getMetaData();
    }

    /**
     * Specification:
     * - Removes the current index
     *
     * @api
     *
     * @return \Elastica\Response
     */
    public function delete()
    {
        return $this
            ->getFactory()
            ->createSearchIndexManager()
            ->delete();
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param string $key
     * @param string $type
     *
     * @return \Elastica\Document
     */
    public function getDocument($key, $type)
    {
        return $this
            ->getFactory()
            ->createSearchIndexManager()
            ->getDocument($key, $type);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param string $searchString
     * @param int|null $limit
     * @param int|null $offset
     *
     * @return \Elastica\ResultSet
     */
    public function searchKeys($searchString, $limit = null, $offset = null)
    {
        return $this
            ->getFactory()
            ->getSearchClient()
            ->searchKeys($searchString, $limit, $offset);
    }

    /**
     * {@inheritdoc}
     *
     * @deprecated use SearchFacade::transformPageMapToDocumentByMapperName() instead
     *
     * @api
     *
     * @param \Spryker\Zed\Search\Dependency\Plugin\PageMapInterface $pageMap
     * @param array $data
     * @param \Generated\Shared\Transfer\LocaleTransfer $localeTransfer
     *
     * @throws \Spryker\Zed\Search\Business\Exception\InvalidPropertyNameException
     *
     * @return array
     */
    public function transformPageMapToDocument(PageMapInterface $pageMap, array $data, LocaleTransfer $localeTransfer)
    {
        return $this->getFactory()
            ->createPageDataMapper()
            ->mapData($pageMap, $data, $localeTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param array $data
     * @param \Generated\Shared\Transfer\LocaleTransfer $localeTransfer
     * @param string $mapperName
     *
     * @throws \Spryker\Zed\Search\Business\Exception\InvalidPropertyNameException
     *
     * @return array
     */
    public function transformPageMapToDocumentByMapperName(array $data, LocaleTransfer $localeTransfer, $mapperName)
    {
        return $this->getFactory()
            ->createPageDataMapper()
            ->transferDataByMapperName($data, $localeTransfer, $mapperName);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Psr\Log\LoggerInterface $messenger
     *
     * @return void
     */
    public function generatePageIndexMap(LoggerInterface $messenger)
    {
        $this
            ->getFactory()
            ->createIndexMapInstaller($messenger)
            ->install();
    }
}
