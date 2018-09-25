<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\IndexGenerator\Business\ForeignKeysProvider;

use Generated\Shared\Transfer\ForeignKeyFileTransfer;
use Generated\Shared\Transfer\ForeignKeyTableTransfer;
use SimpleXMLElement;
use Spryker\Zed\IndexGenerator\Business\Exception\FailedToLoadXmlException;
use Spryker\Zed\IndexGenerator\Business\SchemaFinder\MergedSchemaFinderInterface;
use Symfony\Component\Finder\SplFileInfo;

class ForeignKeysProvider implements ForeignKeysProviderInterface
{
    /**
     * @var \Spryker\Zed\IndexGenerator\Business\SchemaFinder\MergedSchemaFinderInterface
     */
    protected $finder;

    /**
     * @var string[]
     */
    protected $excludedTables;

    /**
     * @param \Spryker\Zed\IndexGenerator\Business\SchemaFinder\MergedSchemaFinderInterface $finder
     * @param array $excludedTables
     */
    public function __construct(MergedSchemaFinderInterface $finder, array $excludedTables)
    {
        $this->finder = $finder;
        $this->excludedTables = $excludedTables;
    }

    /**
     * @return \Generated\Shared\Transfer\ForeignKeyFileTransfer[]
     */
    public function getForeignKeyList(): array
    {
        $foreignKeyFileTransferCollection = [];

        foreach ($this->finder->findMergedSchemas() as $fileInfo) {
            $foreignKeyFileTransfer = $this->processEntityDefinitionFile($fileInfo);
            if ($foreignKeyFileTransfer !== null) {
                $foreignKeyFileTransferCollection[] = $foreignKeyFileTransfer;
            }
        }

        return $foreignKeyFileTransferCollection;
    }

    /**
     * @param \Symfony\Component\Finder\SplFileInfo $fileInfo
     *
     * @return \Generated\Shared\Transfer\ForeignKeyFileTransfer|null
     */
    protected function processEntityDefinitionFile(SplFileInfo $fileInfo): ?ForeignKeyFileTransfer
    {
        $simpleXmlElement = $this->loadSimpleXmlElement($fileInfo);
        $foreignKeyFileTransfer = $this->createForeignKeyFileTransfer($simpleXmlElement, $fileInfo);

        foreach ($this->getTableXmlElements($simpleXmlElement) as $tableXmlElement) {
            if ($this->isTableExcluded($tableXmlElement)) {
                continue;
            }
            $foreignKeyTableTransfer = $this->processTableXmlElement($tableXmlElement);

            if (count($foreignKeyTableTransfer->getColumns()) > 0) {
                $foreignKeyFileTransfer->addForeignKeyTable($foreignKeyTableTransfer);
            }
        }

        return $foreignKeyFileTransfer;
    }

    /**
     * @param \Symfony\Component\Finder\SplFileInfo $fileInfo
     *
     * @throws \Spryker\Zed\IndexGenerator\Business\Exception\FailedToLoadXmlException
     *
     * @return \SimpleXMLElement
     */
    protected function loadSimpleXmlElement(SplFileInfo $fileInfo): SimpleXMLElement
    {
        $simpleXmlElement = simplexml_load_string($fileInfo->getContents());
        if ($simpleXmlElement === false) {
            throw new FailedToLoadXmlException(sprintf('Could not load xml from file "%s"', $fileInfo->getFilename()));
        }

        return $simpleXmlElement;
    }

    /**
     * @param \SimpleXMLElement $tableXmlElement
     *
     * @return bool
     */
    protected function isTableExcluded(SimpleXMLElement $tableXmlElement): bool
    {
        $tableName = (string)$tableXmlElement['name'];
        if (in_array($tableName, $this->excludedTables, true)) {
            return true;
        }

        return false;
    }

    /**
     * @param \SimpleXMLElement $tableXmlElement
     *
     * @return \Generated\Shared\Transfer\ForeignKeyTableTransfer
     */
    protected function processTableXmlElement(SimpleXMLElement $tableXmlElement): ForeignKeyTableTransfer
    {
        $foreignKeyTableTransfer = new ForeignKeyTableTransfer();
        $foreignKeyTableTransfer->setTableName((string)$tableXmlElement['name']);

        if (!$this->isIndexable($tableXmlElement)) {
            return $foreignKeyTableTransfer;
        }

        $foreignKeyColumnNames = $this->getForeignKeyColumnNames($tableXmlElement);
        $indexedColumnNames = $this->getIndexedColumnNames($tableXmlElement);
        foreach ($foreignKeyColumnNames as $foreignKeyColumnName) {
            if (in_array($foreignKeyColumnName, $indexedColumnNames, true)) {
                continue;
            }
            $foreignKeyTableTransfer->addColumn($foreignKeyColumnName);
        }

        return $foreignKeyTableTransfer;
    }

    /**
     * @param \SimpleXMLElement $tableXmlElement
     *
     * @return bool
     */
    protected function isIndexable(SimpleXMLElement $tableXmlElement): bool
    {
        return ($tableXmlElement->xpath('behavior[@name="archivable"]') === false || count($tableXmlElement->xpath('behavior[@name="archivable"]')) === 0);
    }

    /**
     * @param \SimpleXMLElement $tableXmlElement
     *
     * @return array
     */
    protected function getForeignKeyColumnNames(SimpleXMLElement $tableXmlElement): array
    {
        $foreignKeyColumnNames = [];
        $foreignKeyReferencesXmlElement = $tableXmlElement->xpath('foreign-key/reference');

        if ($foreignKeyReferencesXmlElement === false) {
            return $foreignKeyColumnNames;
        }

        foreach ($foreignKeyReferencesXmlElement as $referenceXmlElement) {
            $foreignKeyColumnNames[] = (string)$referenceXmlElement['local'];
        }

        return $foreignKeyColumnNames;
    }

    /**
     * @param \SimpleXMLElement $tableXmlElement
     *
     * @return array
     */
    protected function getIndexedColumnNames(SimpleXMLElement $tableXmlElement): array
    {
        $indexedColumnNames = [];
        $indexColumnXmlElements = $tableXmlElement->xpath('index/index-column');

        if ($indexColumnXmlElements === false) {
            return $indexedColumnNames;
        }
        foreach ($indexColumnXmlElements as $indexColumnXmlElement) {
            $indexedColumnNames[] = (string)$indexColumnXmlElement['name'];
        }

        return $indexedColumnNames;
    }

    /**
     * @param \SimpleXMLElement $xmlElement
     *
     * @return \SimpleXMLElement[]
     */
    protected function getTableXmlElements(SimpleXMLElement $xmlElement): array
    {
        return $xmlElement->xpath('//table') ?: [];
    }

    /**
     * @param \SimpleXMLElement $xmlElement
     * @param \Symfony\Component\Finder\SplFileInfo $fileInfo
     *
     * @return \Generated\Shared\Transfer\ForeignKeyFileTransfer
     */
    protected function createForeignKeyFileTransfer(SimpleXMLElement $xmlElement, SplFileInfo $fileInfo): ForeignKeyFileTransfer
    {
        $foreignKeyFileTransfer = new ForeignKeyFileTransfer();

        $database = $xmlElement->xpath('//database')[0] ?: [];

        $foreignKeyFileTransfer->setNamespace((string)$database['namespace']);
        $foreignKeyFileTransfer->setPackage((string)$database['package']);
        $foreignKeyFileTransfer->setFilename($fileInfo->getFilename());

        return $foreignKeyFileTransfer;
    }
}
