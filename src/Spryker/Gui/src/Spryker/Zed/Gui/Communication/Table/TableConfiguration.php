<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Gui\Communication\Table;

class TableConfiguration
{
    public const SORT_ASC = 'asc';
    public const SORT_DESC = 'desc';

    /**
     * @var string|null
     */
    protected $url;

    /**
     * @var array
     */
    protected $header = [];

    /**
     * @var array
     */
    protected $footer = [];

    /**
     * @var array
     */
    protected $extraColumns = [];

    /**
     * @var int
     */
    protected $pageLength = 0;

    /**
     * If null it will use all fields defined in $header.
     *
     * @var array|null
     */
    protected $searchableFields = null;

    /**
     * @var array
     */
    protected $sortableFields = [];

    /**
     * @var array|null
     */
    protected $defaultSortField = null;

    /**
     * @deprecated Use $defaultSortField instead.
     *
     * @var int
     */
    protected $defaultSortColumnIndex = 0;

    /**
     * @deprecated Use $defaultSortField instead.
     *
     * @var string
     */
    protected $defaultSortDirection = self::SORT_ASC;

    /**
     * @var array
     */
    protected $rawColumns = [];

    /**
     * @var bool
     */
    protected $stateSave = true;

    /**
     * @return array
     */
    public function getRawColumns()
    {
        return $this->rawColumns;
    }

    /**
     * @param array $rawColumns
     *
     * @return $this
     */
    public function setRawColumns(array $rawColumns)
    {
        $this->rawColumns = $rawColumns;

        return $this;
    }

    /**
     * @param string $column
     *
     * @return $this
     */
    public function addRawColumn($column)
    {
        $this->rawColumns[] = $column;

        return $this;
    }

    /**
     * @return array
     */
    public function getHeader()
    {
        return $this->header;
    }

    /**
     * @param array $header Provide php names for table columns
     *   if you are going to user Propel Query as data population
     *
     * @return void
     */
    public function setHeader(array $header)
    {
        if ($this->isAssoc($header)) {
            $this->header = $header;
        }
    }

    /**
     * @return array
     */
    public function getFooter()
    {
        return $this->footer;
    }

    /**
     * @param array $footer
     *
     * @return void
     */
    public function setFooter(array $footer)
    {
        $this->footer = $footer;
    }

    /**
     * @return $this
     */
    public function setFooterFromHeader()
    {
        if (!$this->getHeader()) {
            return $this;
        }

        $headerKeys = array_keys($this->getHeader());
        $this->setFooter($headerKeys);

        return $this;
    }

    /**
     * @param array $extraColumns
     *
     * @return $this
     */
    public function setExtraColumns(array $extraColumns)
    {
        $this->extraColumns = $extraColumns;

        return $this;
    }

    /**
     * @return array
     */
    public function getExtraColumns()
    {
        return $this->extraColumns;
    }

    /**
     * @return array
     */
    public function getSortable()
    {
        return $this->sortableFields;
    }

    /**
     * @param array $sortable
     *
     * @return void
     */
    public function setSortable(array $sortable)
    {
        $this->sortableFields = array_intersect($sortable, array_keys($this->header));
    }

    /**
     * @return array
     */
    public function getSearchable()
    {
        return $this->searchableFields ?: array_keys($this->header);
    }

    /**
     * @param array $searchable
     *
     * @return void
     */
    public function setSearchable(array $searchable)
    {
        $this->searchableFields = $searchable;
    }

    /**
     * @return int
     */
    public function getPageLength()
    {
        return $this->pageLength;
    }

    /**
     * @param int $length
     *
     * @return void
     */
    public function setPageLength($length)
    {
        $this->pageLength = $length;
    }

    /**
     * @return string|null
     */
    public function getUrl()
    {
        return $this->url;
    }

    /**
     * @param string $url
     *
     * @return void
     */
    public function setUrl($url)
    {
        $this->url = $url;
    }

    /**
     * @param string $field
     * @param string $direction
     *
     * @return void
     */
    public function setDefaultSortField($field, $direction = self::SORT_ASC)
    {
        $this->defaultSortField = [$field => $direction];
    }

    /**
     * @return array
     */
    public function getDefaultSortField()
    {
        return $this->defaultSortField;
    }

    /**
     * @deprecated Use setDefaultSortField() instead.
     *
     * @param int $columnIndex
     *
     * @return void
     */
    public function setDefaultSortColumnIndex($columnIndex)
    {
        $this->defaultSortColumnIndex = $columnIndex;
    }

    /**
     * @deprecated Use getDefaultSortField() instead.
     *
     * @return int
     */
    public function getDefaultSortColumnIndex()
    {
        return $this->defaultSortColumnIndex;
    }

    /**
     * @deprecated Use setDefaultSortField() instead.
     *
     * @param string $direction
     *
     * @return void
     */
    public function setDefaultSortDirection($direction)
    {
        $this->defaultSortDirection = $direction;
    }

    /**
     * @deprecated Use getDefaultSortField() instead.
     *
     * @return string
     */
    public function getDefaultSortDirection()
    {
        return $this->defaultSortDirection;
    }

    /**
     * @param array $arr
     *
     * @return bool
     */
    protected function isAssoc(array $arr)
    {
        return (array_values($arr) !== $arr);
    }

    /**
     * @return bool
     */
    public function isStateSave()
    {
        return $this->stateSave;
    }

    /**
     * @param bool $stateSave
     *
     * @return void
     */
    public function setStateSave($stateSave)
    {
        $this->stateSave = $stateSave;
    }
}
