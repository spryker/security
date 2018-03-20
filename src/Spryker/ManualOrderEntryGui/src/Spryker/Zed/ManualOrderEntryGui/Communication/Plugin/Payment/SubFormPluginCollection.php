<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\Payment;

use ArrayAccess;
use Countable;
use Iterator;

class SubFormPluginCollection implements Iterator, Countable, ArrayAccess
{
    /**
     * @var \Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\Payment\SubFormPluginInterface[]
     */
    private $subForms = [];

    /**
     * @var int
     */
    private $position = 0;

    /**
     * @param \Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\Payment\SubFormPluginInterface $subForm
     *
     * @return $this
     */
    public function add(SubFormPluginInterface $subForm)
    {
        $this->subForms[] = $subForm;

        return $this;
    }

    /**
     * @return \Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\Payment\SubFormPluginInterface
     */
    public function current()
    {
        return $this->subForms[$this->position];
    }

    /**
     * @return void
     */
    public function next()
    {
        ++$this->position;
    }

    /**
     * @return int
     */
    public function key()
    {
        return $this->position;
    }

    /**
     * @return bool
     */
    public function valid()
    {
        return isset($this->subForms[$this->position]);
    }

    /**
     * @return void
     */
    public function rewind()
    {
        $this->position = 0;
    }

    /**
     * @return int
     */
    public function count()
    {
        return count($this->subForms);
    }

    /**
     * @param int $offset
     *
     * @return bool
     */
    public function offsetExists($offset)
    {
        return isset($this->subForms[$offset]);
    }

    /**
     * @param int $offset
     *
     * @return \Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\Payment\SubFormPluginInterface
     */
    public function offsetGet($offset)
    {
        return $this->subForms[$offset];
    }

    /**
     * @param int $offset
     * @param \Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\Payment\SubFormPluginInterface $value
     *
     * @return void
     */
    public function offsetSet($offset, $value)
    {
        $this->subForms[$offset] = $value;
    }

    /**
     * @param mixed $offset
     *
     * @return void
     */
    public function offsetUnset($offset)
    {
        unset($this->subForms[$offset]);
    }
}
